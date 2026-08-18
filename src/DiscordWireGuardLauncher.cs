using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Resources;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Discord WireGuard TCP Launcher")]
[assembly: AssemblyDescription("Portable launcher that routes Discord TCP through a WireGuard SOCKS5 proxy")]
[assembly: AssemblyCompany("Local build")]
[assembly: AssemblyProduct("Discord WireGuard TCP Launcher")]
[assembly: AssemblyVersion("2.1.0.0")]
[assembly: AssemblyFileVersion("2.1.0.0")]

internal static class Program
{
    private const string ProxyAddress = "127.0.0.1";
    private const int ProxyPort = 25344;
    private const int WireProxyPort = 25345;
    private const int DirectProxyTestPort = 25346;
    private const int ProxyStartupTimeoutSeconds = 30;
    private const int DiscordStartTimeoutSeconds = 90;
    private const int DiscordStopTimeoutSeconds = 30;
    private const int DiscordStableSeconds = 4;
    private const string WireProxySha256 = "b176b561fd8bf15d828fcab484cfd5b4fb941cb9f61807901ca64b955af27e1f";
    private const string ResourceBaseName = "DiscordWireGuardResources";
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;

    private static volatile bool cancelRequested;

    private sealed class DiscordProcessInfo
    {
        public int ProcessId;
        public string ExecutablePath;
        public string CommandLine;
    }

    private sealed class ProxySession
    {
        private readonly object sync = new object();
        private bool closed;

        public readonly TcpClient Client;
        public readonly bool UseWireGuard;
        public TcpClient Remote;

        public ProxySession(TcpClient client, bool useWireGuard)
        {
            Client = client;
            UseWireGuard = useWireGuard;
        }

        public bool AttachRemote(TcpClient remote)
        {
            lock (sync)
            {
                if (closed)
                {
                    remote.Close();
                    return false;
                }
                Remote = remote;
                return true;
            }
        }

        public void Close()
        {
            lock (sync)
            {
                if (closed)
                {
                    return;
                }
                closed = true;
                try
                {
                    Client.Close();
                }
                catch
                {
                }
                if (Remote != null)
                {
                    try
                    {
                        Remote.Close();
                    }
                    catch
                    {
                    }
                }
            }
        }
    }

    private sealed class SwitchableSocksProxy : IDisposable
    {
        private readonly object sync = new object();
        private readonly string listenAddress;
        private readonly int listenPort;
        private readonly string wireProxyAddress;
        private readonly int wireProxyPort;
        private readonly HashSet<ProxySession> sessions = new HashSet<ProxySession>();
        private TcpListener listener;
        private Thread acceptThread;
        private bool useWireGuard = true;
        private bool stopping;

        public SwitchableSocksProxy(string listenAddress, int listenPort, string wireProxyAddress, int wireProxyPort)
        {
            this.listenAddress = listenAddress;
            this.listenPort = listenPort;
            this.wireProxyAddress = wireProxyAddress;
            this.wireProxyPort = wireProxyPort;
        }

        public void Start()
        {
            listener = new TcpListener(IPAddress.Parse(listenAddress), listenPort);
            listener.Start();
            acceptThread = new Thread(AcceptLoop);
            acceptThread.IsBackground = true;
            acceptThread.Name = "Discord SOCKS5 accept loop";
            acceptThread.Start();
        }

        public void SwitchToDirect()
        {
            List<ProxySession> connections;
            lock (sync)
            {
                useWireGuard = false;
                connections = sessions.ToList();
            }

            foreach (ProxySession connection in connections)
            {
                connection.Close();
            }
        }

        public void Stop()
        {
            List<ProxySession> connections;
            lock (sync)
            {
                if (stopping)
                {
                    return;
                }
                stopping = true;
                connections = sessions.ToList();
            }

            if (listener != null)
            {
                try
                {
                    listener.Stop();
                }
                catch
                {
                }
            }
            foreach (ProxySession connection in connections)
            {
                connection.Close();
            }
            if (acceptThread != null && acceptThread.IsAlive)
            {
                acceptThread.Join(3000);
            }
        }

        public void Dispose()
        {
            Stop();
        }

        private void AcceptLoop()
        {
            while (true)
            {
                TcpClient client = null;
                try
                {
                    client = listener.AcceptTcpClient();
                    client.NoDelay = true;
                }
                catch (SocketException)
                {
                    lock (sync)
                    {
                        if (stopping)
                        {
                            return;
                        }
                    }
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                ProxySession session;
                lock (sync)
                {
                    if (stopping)
                    {
                        client.Close();
                        return;
                    }
                    session = new ProxySession(client, useWireGuard);
                    sessions.Add(session);
                }

                ThreadPool.QueueUserWorkItem(ProcessSession, session);
            }
        }

        private void ProcessSession(object state)
        {
            ProxySession session = (ProxySession)state;
            try
            {
                if (session.UseWireGuard)
                {
                    TcpClient remote = ConnectWithTimeout(wireProxyAddress, wireProxyPort, 15000);
                    if (!session.AttachRemote(remote))
                    {
                        return;
                    }
                    Relay(session);
                }
                else
                {
                    HandleDirectSocks(session);
                }
            }
            catch
            {
            }
            finally
            {
                session.Close();
                lock (sync)
                {
                    sessions.Remove(session);
                }
            }
        }

        private static TcpClient ConnectWithTimeout(string host, int port, int timeoutMilliseconds)
        {
            TcpClient client = new TcpClient();
            IAsyncResult result = null;
            try
            {
                result = client.BeginConnect(host, port, null, null);
                if (!result.AsyncWaitHandle.WaitOne(timeoutMilliseconds))
                {
                    throw new System.TimeoutException("A conexao do proxy excedeu o tempo limite.");
                }
                client.EndConnect(result);
                client.NoDelay = true;
                return client;
            }
            catch
            {
                client.Close();
                throw;
            }
            finally
            {
                if (result != null)
                {
                    result.AsyncWaitHandle.Close();
                }
            }
        }

        private static void HandleDirectSocks(ProxySession session)
        {
            NetworkStream clientStream = session.Client.GetStream();
            clientStream.ReadTimeout = 30000;
            clientStream.WriteTimeout = 30000;

            byte[] greeting = ReadExact(clientStream, 2);
            if (greeting[0] != 0x05 || greeting[1] == 0)
            {
                return;
            }
            byte[] methods = ReadExact(clientStream, greeting[1]);
            bool noAuthentication = methods.Any(delegate(byte method) { return method == 0x00; });
            byte[] methodResponse = new byte[] { 0x05, noAuthentication ? (byte)0x00 : (byte)0xff };
            clientStream.Write(methodResponse, 0, methodResponse.Length);
            if (!noAuthentication)
            {
                return;
            }

            byte[] requestHeader = ReadExact(clientStream, 4);
            if (requestHeader[0] != 0x05 || requestHeader[1] != 0x01)
            {
                SendSocksReply(clientStream, 0x07);
                return;
            }

            string targetHost;
            if (requestHeader[3] == 0x01)
            {
                targetHost = new IPAddress(ReadExact(clientStream, 4)).ToString();
            }
            else if (requestHeader[3] == 0x04)
            {
                targetHost = new IPAddress(ReadExact(clientStream, 16)).ToString();
            }
            else if (requestHeader[3] == 0x03)
            {
                int nameLength = ReadExact(clientStream, 1)[0];
                targetHost = Encoding.ASCII.GetString(ReadExact(clientStream, nameLength));
            }
            else
            {
                SendSocksReply(clientStream, 0x08);
                return;
            }

            byte[] portBytes = ReadExact(clientStream, 2);
            int targetPort = (portBytes[0] << 8) | portBytes[1];
            TcpClient remote;
            try
            {
                remote = ConnectWithTimeout(targetHost, targetPort, 20000);
            }
            catch
            {
                SendSocksReply(clientStream, 0x05);
                return;
            }

            if (!session.AttachRemote(remote))
            {
                return;
            }
            SendSocksReply(clientStream, 0x00);
            Relay(session);
        }

        private static void SendSocksReply(Stream stream, byte reply)
        {
            byte[] response = new byte[] { 0x05, reply, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            stream.Write(response, 0, response.Length);
            stream.Flush();
        }

        private static void Relay(ProxySession session)
        {
            NetworkStream clientStream = session.Client.GetStream();
            NetworkStream remoteStream = session.Remote.GetStream();
            Thread reverse = new Thread(delegate()
            {
                CopyUntilClosed(remoteStream, clientStream, session);
            });
            reverse.IsBackground = true;
            reverse.Start();
            CopyUntilClosed(clientStream, remoteStream, session);
            reverse.Join(2000);
        }

        private static void CopyUntilClosed(Stream source, Stream destination, ProxySession session)
        {
            byte[] buffer = new byte[32768];
            try
            {
                while (true)
                {
                    int read = source.Read(buffer, 0, buffer.Length);
                    if (read <= 0)
                    {
                        return;
                    }
                    destination.Write(buffer, 0, read);
                    destination.Flush();
                }
            }
            catch
            {
            }
            finally
            {
                session.Close();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    private enum JobObjectInfoType
    {
        ExtendedLimitInformation = 9
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        JobObjectInfoType informationClass,
        IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [STAThread]
    private static int Main(string[] args)
    {
        bool checkOnly = args.Any(delegate(string value)
        {
            return string.Equals(value, "--check-only", StringComparison.OrdinalIgnoreCase);
        });
        bool noPause = args.Any(delegate(string value)
        {
            return string.Equals(value, "--no-pause", StringComparison.OrdinalIgnoreCase);
        });
        bool offlineCheck = args.Any(delegate(string value)
        {
            return string.Equals(value, "--offline-check", StringComparison.OrdinalIgnoreCase);
        });
        bool existingProxyCheck = args.Any(delegate(string value)
        {
            return string.Equals(value, "--existing-proxy-check", StringComparison.OrdinalIgnoreCase);
        });
        bool directProxyCheck = args.Any(delegate(string value)
        {
            return string.Equals(value, "--direct-proxy-check", StringComparison.OrdinalIgnoreCase);
        });
        bool switchProxyCheck = args.Any(delegate(string value)
        {
            return string.Equals(value, "--switch-proxy-check", StringComparison.OrdinalIgnoreCase);
        });
        bool directDaemon = args.Any(delegate(string value)
        {
            return string.Equals(value, "--direct-daemon", StringComparison.OrdinalIgnoreCase);
        });
        bool daemonHandoffCheck = args.Any(delegate(string value)
        {
            return string.Equals(value, "--daemon-handoff-check", StringComparison.OrdinalIgnoreCase);
        });

        Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
        {
            eventArgs.Cancel = true;
            cancelRequested = true;
            Console.WriteLine("[INFO] Encerramento solicitado. Limpando processos...");
        };

        try
        {
            string requestedConfigPath = GetArgumentValue(args, "--config");
            int proxyDurationSeconds = GetProxyDurationSeconds(args);
            if (directDaemon)
            {
                RunDirectProxyDaemon(args);
                return 0;
            }
            if (daemonHandoffCheck)
            {
                TestDaemonHandoff();
                Console.WriteLine("[OK] Transferencia para auxiliar invisivel validada.");
                return 0;
            }
            if (existingProxyCheck)
            {
                TestDiscordThroughSocks(ProxyPort);
                Console.WriteLine("[OK] Cliente TCP/TLS interno validado pelo proxy existente.");
                return 0;
            }
            if (directProxyCheck)
            {
                TestDirectProxy();
                Console.WriteLine("[OK] Proxy SOCKS5 direto validado.");
                return 0;
            }
            if (switchProxyCheck)
            {
                TestProxySwitchUsingExistingUpstream();
                Console.WriteLine("[OK] Troca WireGuard para TCP direto validada.");
                return 0;
            }
            Run(checkOnly, offlineCheck, requestedConfigPath, proxyDurationSeconds);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("[ERRO] " + exception.Message);
            if (!noPause)
            {
                Console.WriteLine("Pressione ENTER para fechar.");
                Console.ReadLine();
            }
            return 1;
        }
    }

    private static string GetArgumentValue(string[] args, string name)
    {
        for (int index = 0; index < args.Length; index++)
        {
            string value = args[index];
            if (string.Equals(value, name, StringComparison.OrdinalIgnoreCase))
            {
                if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException("O argumento " + name + " exige um caminho de arquivo.");
                }
                return args[index + 1];
            }

            string prefix = name + "=";
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                string result = value.Substring(prefix.Length).Trim('"');
                if (string.IsNullOrWhiteSpace(result))
                {
                    throw new ArgumentException("O argumento " + name + " exige um caminho de arquivo.");
                }
                return result;
            }
        }
        return null;
    }

    private static int GetProxyDurationSeconds(string[] args)
    {
        string value = GetArgumentValue(args, "--proxy-seconds");
        if (string.IsNullOrWhiteSpace(value))
        {
            return 0;
        }

        int seconds;
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) ||
            seconds < 1 || seconds > 3600)
        {
            throw new ArgumentException("--proxy-seconds deve ser um numero entre 1 e 3600.");
        }
        return seconds;
    }

    private static string ResolveWireGuardConfig(string requestedConfigPath)
    {
        if (!string.IsNullOrWhiteSpace(requestedConfigPath))
        {
            return ValidateWireGuardConfigPath(requestedConfigPath);
        }

        string executableDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        string[] localProfiles = Directory.GetFiles(executableDirectory, "*.conf", SearchOption.TopDirectoryOnly);
        if (localProfiles.Length == 1)
        {
            return ValidateWireGuardConfigPath(localProfiles[0]);
        }

        using (OpenFileDialog dialog = new OpenFileDialog())
        {
            dialog.Title = "Selecione o perfil WireGuard";
            dialog.Filter = "Perfil WireGuard (*.conf)|*.conf|Todos os arquivos (*.*)|*.*";
            dialog.CheckFileExists = true;
            dialog.CheckPathExists = true;
            dialog.Multiselect = false;
            dialog.RestoreDirectory = true;
            dialog.InitialDirectory = executableDirectory;
            if (dialog.ShowDialog() != DialogResult.OK)
            {
                throw new OperationCanceledException("Nenhum perfil WireGuard foi selecionado.");
            }
            return ValidateWireGuardConfigPath(dialog.FileName);
        }
    }

    private static string ValidateWireGuardConfigPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("O perfil WireGuard nao foi encontrado.", fullPath);
        }
        if (!string.Equals(Path.GetExtension(fullPath), ".conf", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Selecione um arquivo WireGuard com extensao .conf.");
        }
        return fullPath;
    }

    private static void RunDirectProxyDaemon(string[] args)
    {
        string portText = GetArgumentValue(args, "--direct-port");
        string requestedDiscordRoot = GetArgumentValue(args, "--discord-root");
        int port;
        if (string.IsNullOrWhiteSpace(portText) ||
            !int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port) ||
            port < 1 || port > 65535)
        {
            throw new ArgumentException("A porta interna do proxy direto e invalida.");
        }
        if (string.IsNullOrWhiteSpace(requestedDiscordRoot))
        {
            throw new ArgumentException("A pasta interna do Discord nao foi informada.");
        }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string expectedDiscordRoot = Path.GetFullPath(Path.Combine(localAppData, "Discord"));
        string discordRoot = Path.GetFullPath(requestedDiscordRoot);
        if (!string.Equals(discordRoot, expectedDiscordRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("A pasta informada para o Discord e invalida.");
        }
        if (!Directory.Exists(discordRoot))
        {
            throw new DirectoryNotFoundException("A pasta do Discord nao foi encontrada.");
        }
        if (!IsTcpPortAvailable(ProxyAddress, port))
        {
            throw new InvalidOperationException("A porta do proxy direto em segundo plano esta ocupada.");
        }

        using (SwitchableSocksProxy proxy = new SwitchableSocksProxy(
            ProxyAddress,
            port,
            ProxyAddress,
            WireProxyPort))
        {
            proxy.Start();
            proxy.SwitchToDirect();
            bool selfTest = args.Any(delegate(string value)
            {
                return string.Equals(value, "--daemon-self-test", StringComparison.OrdinalIgnoreCase);
            });
            if (selfTest)
            {
                TestDiscordThroughSocks(port);
            }
            else
            {
                WaitForDiscordExit(discordRoot);
            }
        }
    }

    private static void TestDaemonHandoff()
    {
        int testPort = FindAvailableTcpPort(25450, new HashSet<int>());
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string discordRoot = Path.Combine(localAppData, "Discord");
        string executablePath = Assembly.GetExecutingAssembly().Location;
        string arguments = "--direct-daemon --daemon-self-test --no-pause --direct-port " +
                           testPort.ToString(CultureInfo.InvariantCulture) +
                           " --discord-root \"" + discordRoot + "\"";
        using (Process daemon = StartHiddenProcess(executablePath, arguments, Path.GetDirectoryName(executablePath)))
        {
            if (!daemon.WaitForExit(30000))
            {
                daemon.Kill();
                throw new System.TimeoutException("O autoteste do auxiliar invisivel excedeu o tempo limite.");
            }
            if (daemon.ExitCode != 0)
            {
                throw new InvalidOperationException("O autoteste do auxiliar invisivel retornou erro.");
            }
        }
    }

    private static void StartDirectProxyDaemon(int port, string discordRoot)
    {
        string executablePath = Assembly.GetExecutingAssembly().Location;
        string arguments = "--direct-daemon --no-pause --direct-port " +
                           port.ToString(CultureInfo.InvariantCulture) +
                           " --discord-root \"" + discordRoot + "\"";
        Process daemon = StartHiddenProcess(executablePath, arguments, Path.GetDirectoryName(executablePath));
        bool ready = false;
        try
        {
            Stopwatch timeout = Stopwatch.StartNew();
            while (timeout.Elapsed < TimeSpan.FromSeconds(15))
            {
                daemon.Refresh();
                if (daemon.HasExited)
                {
                    throw new InvalidOperationException("O auxiliar do proxy direto encerrou durante a inicializacao.");
                }
                if (CanConnectToProxy(ProxyAddress, port, 500))
                {
                    TestDiscordThroughSocks(port);
                    ready = true;
                    return;
                }
                Thread.Sleep(100);
            }
            throw new System.TimeoutException("O auxiliar do proxy direto nao ficou pronto.");
        }
        finally
        {
            if (ready)
            {
                daemon.Dispose();
            }
            else
            {
                StopTrackedProcess(daemon);
            }
        }
    }

    private static void Run(bool checkOnly, bool offlineCheck, string requestedConfigPath, int proxyDurationSeconds)
    {
        if (IsRunningElevated())
        {
            throw new InvalidOperationException("Execute este programa sem privilegios de Administrador.");
        }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            throw new InvalidOperationException("LOCALAPPDATA nao esta disponivel.");
        }

        string discordRoot = Path.Combine(localAppData, "Discord");
        string updatePath = Path.Combine(discordRoot, "Update.exe");
        if (!File.Exists(updatePath))
        {
            throw new FileNotFoundException("O atualizador do Discord nao foi encontrado.", updatePath);
        }

        EnsureNoOfficialWireGuardTunnel();

        bool mutexOwned = false;
        Mutex launcherMutex = null;
        Process wireProxyProcess = null;
        SwitchableSocksProxy switchableProxy = null;
        IntPtr wireProxyJob = IntPtr.Zero;
        string runtimeRoot = Path.Combine(localAppData, "DiscordWireGuardProxy");
        string runtimeDirectory = null;
        string wireProxyPath = null;
        string wireGuardPath = null;
        string sourceWireGuardPath = null;
        string wrapperPath = null;
        int discordProxyPort = ProxyPort;
        int wireProxyPort = WireProxyPort;
        bool discordStarted = false;

        try
        {
            if (!offlineCheck)
            {
                launcherMutex = new Mutex(false, "Local\\DiscordWireGuardTcpProxyLauncher");
                try
                {
                    mutexOwned = launcherMutex.WaitOne(0, false);
                }
                catch (AbandonedMutexException)
                {
                    mutexOwned = true;
                }

                if (!mutexOwned)
                {
                    throw new InvalidOperationException("Outra instancia deste launcher ja esta em execucao.");
                }
            }

            sourceWireGuardPath = ResolveWireGuardConfig(requestedConfigPath);
            Console.WriteLine("[INFO] Perfil WireGuard: " + Path.GetFileName(sourceWireGuardPath));

            if (!offlineCheck)
            {
                HashSet<int> selectedPorts = new HashSet<int>();
                discordProxyPort = FindAvailableTcpPort(ProxyPort, selectedPorts);
                selectedPorts.Add(discordProxyPort);
                wireProxyPort = FindAvailableTcpPort(WireProxyPort, selectedPorts);
                Console.WriteLine(
                    "[INFO] Portas TCP livres: Discord " + discordProxyPort.ToString(CultureInfo.InvariantCulture) +
                    ", WireGuard " + wireProxyPort.ToString(CultureInfo.InvariantCulture) + ".");
            }

            Directory.CreateDirectory(runtimeRoot);
            runtimeDirectory = CreatePrivateRuntimeDirectory(runtimeRoot);
            wireProxyPath = Path.Combine(runtimeDirectory, "wireproxy.exe");
            wireGuardPath = Path.Combine(runtimeDirectory, "wireguard.conf");
            wrapperPath = Path.Combine(runtimeDirectory, "wireproxy.conf");

            ExtractEmbeddedWireProxy(wireProxyPath);
            CopyWireGuardConfig(sourceWireGuardPath, wireGuardPath);
            string wrapperText = "WGConfig = " + wireGuardPath + Environment.NewLine +
                                 Environment.NewLine +
                                 "[Socks5]" + Environment.NewLine +
                                 "BindAddress = " + ProxyAddress + ":" + wireProxyPort.ToString(CultureInfo.InvariantCulture) + Environment.NewLine;
            File.WriteAllText(wrapperPath, wrapperText, Encoding.ASCII);

            ValidateWireProxyConfig(wireProxyPath, wrapperPath);

            if (offlineCheck)
            {
                Console.WriteLine("[OK] wireproxy interno, SHA256 e perfil externo validados.");
                return;
            }

            wireProxyJob = CreateKillOnCloseJob();
            switchableProxy = new SwitchableSocksProxy(ProxyAddress, discordProxyPort, ProxyAddress, wireProxyPort);
            switchableProxy.Start();

            Console.WriteLine("[INFO] Iniciando o proxy TCP local pelo WireGuard...");
            wireProxyProcess = StartHiddenProcess(wireProxyPath, "-c \"" + wrapperPath + "\" -s", runtimeDirectory);
            if (!AssignProcessToJobObject(wireProxyJob, wireProxyProcess.Handle))
            {
                throw new InvalidOperationException("Nao foi possivel vincular wireproxy ao supervisor do Windows.");
            }

            WaitForProxy(wireProxyProcess, ProxyAddress, wireProxyPort, ProxyStartupTimeoutSeconds);

            Console.WriteLine("[INFO] Testando o acesso TCP ao Discord pelo WireGuard...");
            TestDiscordThroughSocks(discordProxyPort);
            DeleteSensitiveFile(wireGuardPath);
            wireGuardPath = null;
            DeleteSensitiveFile(wrapperPath);
            wrapperPath = null;

            if (checkOnly)
            {
                Console.WriteLine("[OK] WireGuard e proxy SOCKS5 funcionando corretamente.");
                return;
            }

            Console.WriteLine("[INFO] Fechando a instancia atual do Discord...");
            StopDiscordProcesses(discordRoot, DiscordStopTimeoutSeconds);

            string proxyArgument = "--proxy-server=socks5://" + ProxyAddress + ":" + discordProxyPort.ToString(CultureInfo.InvariantCulture);
            Console.WriteLine("[INFO] Reiniciando o Discord com o proxy TCP...");
            discordStarted = true;
            StartDiscord(updatePath, discordRoot, proxyArgument);
            WaitForProxiedDiscord(discordRoot, proxyArgument, wireProxyProcess, DiscordStartTimeoutSeconds, DiscordStableSeconds);

            Console.WriteLine();
            Console.WriteLine("[OK] O TCP do Discord esta usando WireGuard. O UDP nao foi alterado.");
            if (proxyDurationSeconds > 0)
            {
                Console.WriteLine(
                    "[INFO] Mantendo o WireGuard por mais " +
                    proxyDurationSeconds.ToString(CultureInfo.InvariantCulture) + " segundos.");
                bool discordStillRunning = WaitForProxyDuration(discordRoot, wireProxyProcess, proxyDurationSeconds);
                if (!discordStillRunning)
                {
                    discordStarted = false;
                    Console.WriteLine("[OK] Discord foi fechado; proxy WireGuard encerrado.");
                    return;
                }
            }
            else
            {
                Console.WriteLine("[INFO] Discord estabilizado. Encerrando o WireGuard imediatamente.");
            }

            Console.WriteLine("[INFO] Alterando o proxy para TCP direto...");
            HashSet<int> processIdsBeforeSwitch = new HashSet<int>(
                GetDiscordProcesses(discordRoot).Select(delegate(DiscordProcessInfo process) { return process.ProcessId; }));

            switchableProxy.SwitchToDirect();

            StopTrackedProcess(wireProxyProcess);
            wireProxyProcess = null;
            if (wireProxyJob != IntPtr.Zero)
            {
                CloseHandle(wireProxyJob);
                wireProxyJob = IntPtr.Zero;
            }

            TestDiscordThroughSocks(discordProxyPort);
            WaitForSameDiscordInstance(discordRoot, processIdsBeforeSwitch, DiscordStartTimeoutSeconds, DiscordStableSeconds);
            Console.WriteLine("[OK] WireGuard encerrado. A mesma instancia do Discord agora usa TCP direto.");

            Console.WriteLine("[INFO] Transferindo o proxy direto para segundo plano...");
            switchableProxy.Dispose();
            switchableProxy = null;
            StartDirectProxyDaemon(discordProxyPort, discordRoot);
            discordStarted = false;
            Console.WriteLine("[OK] A janela sera fechada. O auxiliar invisivel termina junto com o Discord.");
            Thread.Sleep(1500);
        }
        catch
        {
            if (discordStarted)
            {
                try
                {
                    StopDiscordProcesses(discordRoot, DiscordStopTimeoutSeconds);
                }
                catch
                {
                    Console.Error.WriteLine("[AVISO] Nao foi possivel fechar o Discord apos o erro.");
                }
            }
            throw;
        }
        finally
        {
            if (switchableProxy != null)
            {
                switchableProxy.Dispose();
            }
            StopTrackedProcess(wireProxyProcess);
            if (wireProxyJob != IntPtr.Zero)
            {
                CloseHandle(wireProxyJob);
            }

            DeleteSensitiveFile(wireGuardPath);
            DeleteSensitiveFile(wrapperPath);
            DeleteRegularFile(wireProxyPath);
            DeleteRuntimeDirectory(runtimeDirectory, runtimeRoot);

            if (mutexOwned && launcherMutex != null)
            {
                launcherMutex.ReleaseMutex();
            }
            if (launcherMutex != null)
            {
                launcherMutex.Dispose();
            }
        }
    }

    private static bool IsRunningElevated()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    private static void EnsureNoOfficialWireGuardTunnel()
    {
        ServiceController[] services = ServiceController.GetServices();
        try
        {
            foreach (ServiceController service in services)
            {
                if (service.ServiceName.StartsWith("WireGuardTunnel$", StringComparison.OrdinalIgnoreCase) &&
                    service.Status == ServiceControllerStatus.Running)
                {
                    throw new InvalidOperationException("Um tunel do aplicativo WireGuard ja esta ativo. Desligue-o primeiro.");
                }
            }
        }
        finally
        {
            foreach (ServiceController service in services)
            {
                service.Dispose();
            }
        }
    }

    private static string CreatePrivateRuntimeDirectory(string runtimeRoot)
    {
        string directory = Path.Combine(
            runtimeRoot,
            "run-" + Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        try
        {
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            FileSystemAccessRule rule = new FileSystemAccessRule(
                identity.User,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow);
            security.AddAccessRule(rule);
            Directory.SetAccessControl(directory, security);
        }
        finally
        {
            identity.Dispose();
        }

        return directory;
    }

    private static void ExtractEmbeddedWireProxy(string wireProxyPath)
    {
        ResourceManager resources = new ResourceManager(ResourceBaseName, Assembly.GetExecutingAssembly());
        byte[] wireProxyBytes = resources.GetObject("wireproxy") as byte[];
        if (wireProxyBytes == null)
        {
            throw new InvalidOperationException("O recurso interno do wireproxy esta ausente.");
        }

        string actualHash = ComputeSha256(wireProxyBytes);
        if (!string.Equals(actualHash, WireProxySha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("A verificacao SHA256 do wireproxy interno falhou.");
        }

        File.WriteAllBytes(wireProxyPath, wireProxyBytes);
    }

    private static void CopyWireGuardConfig(string sourcePath, string destinationPath)
    {
        byte[] configBytes = null;
        try
        {
            configBytes = File.ReadAllBytes(sourcePath);
            File.WriteAllBytes(destinationPath, configBytes);
        }
        finally
        {
            if (configBytes != null)
            {
                Array.Clear(configBytes, 0, configBytes.Length);
            }
        }
    }

    private static string ComputeSha256(byte[] data)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(data);
            StringBuilder result = new StringBuilder(hash.Length * 2);
            foreach (byte value in hash)
            {
                result.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            }
            return result.ToString();
        }
    }

    private static void ValidateWireProxyConfig(string executablePath, string configPath)
    {
        using (Process process = StartHiddenProcess(executablePath, "-c \"" + configPath + "\" -n -s", Path.GetDirectoryName(executablePath)))
        {
            if (!process.WaitForExit(30000))
            {
                process.Kill();
                throw new System.TimeoutException("A validacao da configuracao do wireproxy excedeu 30 segundos.");
            }
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException("O wireproxy rejeitou a configuracao WireGuard incorporada.");
            }
        }
    }

    private static Process StartHiddenProcess(string fileName, string arguments, string workingDirectory)
    {
        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = fileName;
        startInfo.Arguments = arguments;
        startInfo.WorkingDirectory = workingDirectory;
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.WindowStyle = ProcessWindowStyle.Hidden;

        Process process = new Process();
        process.StartInfo = startInfo;
        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException("Nao foi possivel iniciar " + Path.GetFileName(fileName) + ".");
        }
        return process;
    }

    private static IntPtr CreateKillOnCloseJob()
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            throw new InvalidOperationException("Nao foi possivel criar o supervisor de processos do Windows.");
        }

        JobObjectExtendedLimitInformation information = new JobObjectExtendedLimitInformation();
        information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        int length = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
        IntPtr pointer = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(information, pointer, false);
            if (!SetInformationJobObject(job, JobObjectInfoType.ExtendedLimitInformation, pointer, (uint)length))
            {
                CloseHandle(job);
                throw new InvalidOperationException("Nao foi possivel configurar o supervisor de processos do Windows.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }

        return job;
    }

    private static bool IsTcpPortAvailable(string address, int port)
    {
        TcpListener listener = null;
        try
        {
            listener = new TcpListener(IPAddress.Parse(address), port);
            listener.Start();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        finally
        {
            if (listener != null)
            {
                listener.Stop();
            }
        }
    }

    private static int FindAvailableTcpPort(int preferredPort, HashSet<int> excludedPorts)
    {
        const int searchLength = 1000;
        for (int offset = 0; offset < searchLength; offset++)
        {
            int candidate = preferredPort + offset;
            if (candidate > 65535)
            {
                break;
            }
            if (excludedPorts != null && excludedPorts.Contains(candidate))
            {
                continue;
            }
            if (IsTcpPortAvailable(ProxyAddress, candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            "Nenhuma porta TCP livre foi encontrada entre " +
            preferredPort.ToString(CultureInfo.InvariantCulture) + " e " +
            Math.Min(65535, preferredPort + searchLength - 1).ToString(CultureInfo.InvariantCulture) + ".");
    }

    private static bool CanConnectToProxy(string address, int port, int timeoutMilliseconds)
    {
        using (TcpClient client = new TcpClient())
        {
            IAsyncResult result = null;
            try
            {
                result = client.BeginConnect(address, port, null, null);
                if (!result.AsyncWaitHandle.WaitOne(timeoutMilliseconds))
                {
                    return false;
                }
                client.EndConnect(result);
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
            finally
            {
                if (result != null)
                {
                    result.AsyncWaitHandle.Close();
                }
            }
        }
    }

    private static void WaitForProxy(Process process, string address, int port, int timeoutSeconds)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < TimeSpan.FromSeconds(timeoutSeconds))
        {
            process.Refresh();
            if (process.HasExited)
            {
                throw new InvalidOperationException("wireproxy encerrou antes de abrir a porta SOCKS5.");
            }
            if (CanConnectToProxy(address, port, 500))
            {
                return;
            }
            Thread.Sleep(250);
        }
        throw new System.TimeoutException("O proxy SOCKS5 nao ficou pronto dentro do tempo limite.");
    }

    private static void TestDiscordThroughSocks(int proxyPort)
    {
        const string host = "discord.com";
        using (TcpClient client = new TcpClient())
        {
            client.ReceiveTimeout = 30000;
            client.SendTimeout = 30000;
            client.Connect(ProxyAddress, proxyPort);
            using (NetworkStream network = client.GetStream())
            {
                byte[] greeting = new byte[] { 0x05, 0x01, 0x00 };
                network.Write(greeting, 0, greeting.Length);
                byte[] greetingResponse = ReadExact(network, 2);
                if (greetingResponse[0] != 0x05 || greetingResponse[1] != 0x00)
                {
                    throw new InvalidOperationException("O proxy SOCKS5 recusou autenticacao sem senha.");
                }

                byte[] hostBytes = Encoding.ASCII.GetBytes(host);
                byte[] request = new byte[7 + hostBytes.Length];
                request[0] = 0x05;
                request[1] = 0x01;
                request[2] = 0x00;
                request[3] = 0x03;
                request[4] = (byte)hostBytes.Length;
                Buffer.BlockCopy(hostBytes, 0, request, 5, hostBytes.Length);
                request[5 + hostBytes.Length] = 0x01;
                request[6 + hostBytes.Length] = 0xbb;
                network.Write(request, 0, request.Length);

                byte[] responseHeader = ReadExact(network, 4);
                if (responseHeader[0] != 0x05 || responseHeader[1] != 0x00)
                {
                    throw new InvalidOperationException("O WireGuard nao conseguiu conectar ao Discord pelo SOCKS5.");
                }

                int addressLength;
                if (responseHeader[3] == 0x01)
                {
                    addressLength = 4;
                }
                else if (responseHeader[3] == 0x04)
                {
                    addressLength = 16;
                }
                else if (responseHeader[3] == 0x03)
                {
                    addressLength = ReadExact(network, 1)[0];
                }
                else
                {
                    throw new InvalidOperationException("O proxy SOCKS5 retornou um endereco invalido.");
                }
                ReadExact(network, addressLength + 2);

                using (SslStream tls = new SslStream(network, false))
                {
                    tls.ReadTimeout = 30000;
                    tls.WriteTimeout = 30000;
                    tls.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
                    string httpRequest = "GET /api/v10/gateway HTTP/1.1\r\n" +
                                         "Host: discord.com\r\n" +
                                         "User-Agent: DiscordWireGuardLauncher/1.0\r\n" +
                                         "Connection: close\r\n\r\n";
                    byte[] httpBytes = Encoding.ASCII.GetBytes(httpRequest);
                    tls.Write(httpBytes, 0, httpBytes.Length);
                    tls.Flush();

                    string statusLine = ReadLine(tls, 1024);
                    if (string.IsNullOrWhiteSpace(statusLine) || !statusLine.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("O teste TCP nao recebeu uma resposta HTTP valida do Discord.");
                    }
                }
            }
        }
    }

    private static void TestDirectProxy()
    {
        TcpListener occupiedPort = new TcpListener(IPAddress.Parse(ProxyAddress), DirectProxyTestPort);
        int selectedPort;
        occupiedPort.Start();
        try
        {
            selectedPort = FindAvailableTcpPort(DirectProxyTestPort, new HashSet<int>());
        }
        finally
        {
            occupiedPort.Stop();
        }
        if (selectedPort == DirectProxyTestPort)
        {
            throw new InvalidOperationException("A selecao automatica nao ignorou a porta ocupada.");
        }

        using (SwitchableSocksProxy proxy = new SwitchableSocksProxy(
            ProxyAddress,
            selectedPort,
            ProxyAddress,
            WireProxyPort))
        {
            proxy.Start();
            proxy.SwitchToDirect();
            TestDiscordThroughSocks(selectedPort);
        }
    }

    private static void TestProxySwitchUsingExistingUpstream()
    {
        if (!IsTcpPortAvailable(ProxyAddress, DirectProxyTestPort))
        {
            throw new InvalidOperationException("A porta do autoteste de troca esta em uso.");
        }
        if (!CanConnectToProxy(ProxyAddress, ProxyPort, 1000))
        {
            throw new InvalidOperationException("O proxy WireGuard existente nao esta disponivel para o autoteste.");
        }

        using (SwitchableSocksProxy proxy = new SwitchableSocksProxy(
            ProxyAddress,
            DirectProxyTestPort,
            ProxyAddress,
            ProxyPort))
        {
            proxy.Start();
            TestDiscordThroughSocks(DirectProxyTestPort);
            proxy.SwitchToDirect();
            TestDiscordThroughSocks(DirectProxyTestPort);
        }
    }

    private static byte[] ReadExact(Stream stream, int count)
    {
        byte[] buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = stream.Read(buffer, offset, count - offset);
            if (read <= 0)
            {
                throw new EndOfStreamException("A conexao SOCKS5 terminou inesperadamente.");
            }
            offset += read;
        }
        return buffer;
    }

    private static string ReadLine(Stream stream, int maximumBytes)
    {
        List<byte> bytes = new List<byte>();
        while (bytes.Count < maximumBytes)
        {
            int value = stream.ReadByte();
            if (value < 0)
            {
                break;
            }
            if (value == 10)
            {
                break;
            }
            if (value != 13)
            {
                bytes.Add((byte)value);
            }
        }
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private static List<DiscordProcessInfo> GetDiscordProcesses(string discordRoot)
    {
        List<DiscordProcessInfo> processes = new List<DiscordProcessInfo>();
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process WHERE Name = 'Discord.exe'"))
        using (ManagementObjectCollection results = searcher.Get())
        {
            foreach (ManagementObject result in results)
            {
                using (result)
                {
                    string executablePath = result["ExecutablePath"] as string;
                    if (string.IsNullOrWhiteSpace(executablePath) || !IsPathUnderRoot(executablePath, discordRoot))
                    {
                        continue;
                    }

                    DiscordProcessInfo info = new DiscordProcessInfo();
                    info.ProcessId = Convert.ToInt32((uint)result["ProcessId"], CultureInfo.InvariantCulture);
                    info.ExecutablePath = executablePath;
                    info.CommandLine = result["CommandLine"] as string;
                    processes.Add(info);
                }
            }
        }
        return processes;
    }

    private static bool IsPathUnderRoot(string path, string root)
    {
        try
        {
            string fullPath = Path.GetFullPath(path);
            string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void StopDiscordProcesses(string discordRoot, int timeoutSeconds)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        do
        {
            List<DiscordProcessInfo> processes = GetDiscordProcesses(discordRoot);
            if (processes.Count == 0)
            {
                return;
            }

            foreach (DiscordProcessInfo info in processes)
            {
                try
                {
                    using (Process process = Process.GetProcessById(info.ProcessId))
                    {
                        process.Kill();
                    }
                }
                catch (ArgumentException)
                {
                }
                catch (InvalidOperationException)
                {
                }
            }
            Thread.Sleep(250);
        }
        while (stopwatch.Elapsed < TimeSpan.FromSeconds(timeoutSeconds));

        if (GetDiscordProcesses(discordRoot).Count > 0)
        {
            throw new System.TimeoutException("O Discord nao fechou dentro do tempo limite.");
        }
    }

    private static void StartDiscord(string updatePath, string discordRoot, string proxyArgument)
    {
        string arguments = "--processStart Discord.exe";
        if (!string.IsNullOrWhiteSpace(proxyArgument))
        {
            arguments += " --process-start-args \"" + proxyArgument + "\"";
        }
        using (Process updater = StartHiddenProcess(updatePath, arguments, discordRoot))
        {
            if (!updater.WaitForExit(60000))
            {
                updater.Kill();
                throw new System.TimeoutException("O atualizador do Discord excedeu 60 segundos.");
            }
            if (updater.ExitCode != 0)
            {
                throw new InvalidOperationException("O atualizador do Discord retornou o codigo " + updater.ExitCode.ToString(CultureInfo.InvariantCulture) + ".");
            }
        }
    }

    private static void WaitForProxiedDiscord(
        string discordRoot,
        string proxyArgument,
        Process wireProxyProcess,
        int timeoutSeconds,
        int stableSeconds)
    {
        Stopwatch timeout = Stopwatch.StartNew();
        Stopwatch stable = null;
        while (timeout.Elapsed < TimeSpan.FromSeconds(timeoutSeconds))
        {
            ThrowIfCancellationRequested();
            wireProxyProcess.Refresh();
            if (wireProxyProcess.HasExited)
            {
                throw new InvalidOperationException("wireproxy encerrou durante a inicializacao do Discord.");
            }

            bool found = GetDiscordProcesses(discordRoot).Any(delegate(DiscordProcessInfo process)
            {
                return !string.IsNullOrWhiteSpace(process.CommandLine) &&
                       process.CommandLine.IndexOf(proxyArgument, StringComparison.OrdinalIgnoreCase) >= 0;
            });

            if (found)
            {
                if (stable == null)
                {
                    stable = Stopwatch.StartNew();
                }
                else if (stable.Elapsed >= TimeSpan.FromSeconds(stableSeconds))
                {
                    return;
                }
            }
            else
            {
                stable = null;
            }
            Thread.Sleep(250);
        }

        throw new System.TimeoutException("O Discord nao iniciou com o argumento de proxy esperado.");
    }

    private static bool WaitForProxyDuration(string discordRoot, Process wireProxyProcess, int durationSeconds)
    {
        Stopwatch duration = Stopwatch.StartNew();
        while (duration.Elapsed < TimeSpan.FromSeconds(durationSeconds))
        {
            ThrowIfCancellationRequested();
            wireProxyProcess.Refresh();
            if (wireProxyProcess.HasExited)
            {
                throw new InvalidOperationException("wireproxy encerrou inesperadamente. O Discord sera fechado para evitar reconexao sem proxy.");
            }

            if (GetDiscordProcesses(discordRoot).Count == 0)
            {
                Thread.Sleep(2000);
                if (GetDiscordProcesses(discordRoot).Count == 0)
                {
                    return false;
                }
            }
            Thread.Sleep(250);
        }
        return true;
    }

    private static void WaitForSameDiscordInstance(
        string discordRoot,
        HashSet<int> processIdsBeforeSwitch,
        int timeoutSeconds,
        int stableSeconds)
    {
        Stopwatch timeout = Stopwatch.StartNew();
        Stopwatch stable = null;
        while (timeout.Elapsed < TimeSpan.FromSeconds(timeoutSeconds))
        {
            ThrowIfCancellationRequested();
            List<DiscordProcessInfo> processes = GetDiscordProcesses(discordRoot);
            bool sameProcessFound = processes.Any(delegate(DiscordProcessInfo process)
            {
                return processIdsBeforeSwitch.Contains(process.ProcessId);
            });

            if (sameProcessFound)
            {
                if (stable == null)
                {
                    stable = Stopwatch.StartNew();
                }
                else if (stable.Elapsed >= TimeSpan.FromSeconds(stableSeconds))
                {
                    return;
                }
            }
            else
            {
                stable = null;
            }
            Thread.Sleep(250);
        }

        throw new System.TimeoutException("A instancia original do Discord nao permaneceu ativa depois da troca do TCP.");
    }

    private static void WaitForDiscordExit(string discordRoot)
    {
        while (true)
        {
            ThrowIfCancellationRequested();
            if (GetDiscordProcesses(discordRoot).Count == 0)
            {
                Thread.Sleep(2000);
                if (GetDiscordProcesses(discordRoot).Count == 0)
                {
                    return;
                }
            }
            Thread.Sleep(1000);
        }
    }

    private static void ThrowIfCancellationRequested()
    {
        if (cancelRequested)
        {
            throw new OperationCanceledException("Execucao cancelada pelo usuario.");
        }
    }

    private static void StopTrackedProcess(Process process)
    {
        if (process == null)
        {
            return;
        }
        try
        {
            process.Refresh();
            if (!process.HasExited)
            {
                process.Kill();
                process.WaitForExit(5000);
            }
        }
        catch
        {
        }
        finally
        {
            process.Dispose();
        }
    }

    private static void DeleteSensitiveFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        try
        {
            long length = new FileInfo(path).Length;
            byte[] zeros = new byte[4096];
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                long written = 0;
                while (written < length)
                {
                    int count = (int)Math.Min((long)zeros.Length, length - written);
                    stream.Write(zeros, 0, count);
                    written += count;
                }
                stream.Flush(true);
            }
            File.Delete(path);
        }
        catch
        {
            try
            {
                File.Delete(path);
            }
            catch
            {
            }
        }
    }

    private static void DeleteRegularFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    private static void DeleteRuntimeDirectory(string runtimeDirectory, string runtimeRoot)
    {
        if (string.IsNullOrWhiteSpace(runtimeDirectory) || string.IsNullOrWhiteSpace(runtimeRoot))
        {
            return;
        }
        if (!IsPathUnderRoot(runtimeDirectory, runtimeRoot) ||
            !Path.GetFileName(runtimeDirectory).StartsWith("run-", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        try
        {
            Directory.Delete(runtimeDirectory, false);
        }
        catch
        {
        }
    }
}
