using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;

namespace Memory_Tools
{
    public static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("gdi32.dll")]
        public static extern uint SetPixel(IntPtr hdc, int X, int Y, uint crColor);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("user32.dll")]
        public static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ScreenToClient(IntPtr hWnd, ref POINT lpPoint);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        public static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

        [DllImport("user32.dll")]
        public static extern IntPtr GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr CreateWindowExA(int dwExStyle, [MarshalAs(UnmanagedType.LPStr)] string lpClassName, [MarshalAs(UnmanagedType.LPStr)] string lpWindowName, WindowStyles dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetParent(IntPtr childHWND, IntPtr newHWND);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out ulong lpExitCode);

        [Flags]
        public enum WindowStyles : uint
        {
            WS_BORDER = 0x800000,
            WS_CAPTION = 0xc00000,
            WS_CHILD = 0x40000000,
            WS_CLIPCHILDREN = 0x2000000,
            WS_CLIPSIBLINGS = 0x4000000,
            WS_DISABLED = 0x8000000,
            WS_DLGFRAME = 0x400000,
            WS_GROUP = 0x20000,
            WS_HSCROLL = 0x100000,
            WS_MAXIMIZE = 0x1000000,
            WS_MAXIMIZEBOX = 0x10000,
            WS_MINIMIZE = 0x20000000,
            WS_MINIMIZEBOX = 0x20000,
            WS_OVERLAPPED = 0x0,
            WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_SIZEFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
            WS_POPUP = 0x80000000u,
            WS_POPUPWINDOW = WS_POPUP | WS_BORDER | WS_SYSMENU,
            WS_SIZEFRAME = 0x40000,
            WS_SYSMENU = 0x80000,
            WS_TABSTOP = 0x10000,
            WS_VISIBLE = 0x10000000,
            WS_VSCROLL = 0x200000
        }

        [Flags]
        public enum LoadLibraryFlags : uint
        {
            None = 0,
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int X;
            public int Y;

            public POINT(int x, int y)
            {
                X = x;
                Y = y;
            }

            public static implicit operator System.Drawing.Point(POINT p)
            {
                return new System.Drawing.Point(p.X, p.Y);
            }

            public static implicit operator POINT(System.Drawing.Point p)
            {
                return new POINT(p.X, p.Y);
            }
        }

        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200,
            THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags; //set this to an appropriate value
                                      // Retrieved by CONTEXT_DEBUG_REGISTERS
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            // Retrieved by CONTEXT_FLOATING_POINT
            public FLOATING_SAVE_AREA FloatSave;
            // Retrieved by CONTEXT_SEGMENTS
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            // Retrieved by CONTEXT_INTEGER
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            // Retrieved by CONTEXT_CONTROL
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            // Retrieved by CONTEXT_EXTENDED_REGISTERS
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        // Next x64

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", High, Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public /*ushort*/ulong ControlWord;
            public /*ushort*/ulong StatusWord;
            public /*byte*/ulong TagWord;
            public /*byte*/ulong Reserved1;
            public /*ushort*/ulong ErrorOpcode;
            public /*uint*/ulong ErrorOffset;
            public /*ushort*/ulong ErrorSelector;
            public /*ushort*/ulong Reserved2;
            public /*uint*/ulong DataOffset;
            public /*ushort*/ulong DataSelector;
            public /*ushort*/ulong Reserved3;
            public /*uint*/ulong MxCsr;
            public /*uint*/ulong MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public /*uint*/ulong MxCsr;

            public /*ushort*/ulong SegCs;
            public /*ushort*/ulong SegDs;
            public /*ushort*/ulong SegEs;
            public /*ushort*/ulong SegFs;
            public /*ushort*/ulong SegGs;
            public /*ushort*/ulong SegSs;
            public /*uint*/ulong EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }
    }

    public class ThreadItem
    {
        public int Id { get; set; }

        public DateTime TimeStarted { get; set; }

        public string StartAddress { get; set; }

        public System.Diagnostics.ThreadState State { get; set; }

        public bool IsSuspended { get; set; }
    }

    public class OutputViewItem
    {
        public string Address { get; set; }
        public byte ByteData { get; set; }
        public string Message { get; set; }
        public Brush ColorData { get; set; }
    }

    public partial class MainWindow : Window
    {
        public static Process SelectedProcess;
        public static MainWindow CurrentInstance;
        public static bool has_selected_process = false;
        public static bool IsPaused = true;
        public static bool HasStartedCorruption = false;
        public static Color ColorPaint = Color.FromRgb(0, 0, 0);
        public static bool IsDrawing = false;
        public static System.Windows.Forms.ColorDialog color_dlg = new System.Windows.Forms.ColorDialog();
        public static Thread Proc_check = new Thread(CheckProcess);
        public static NativeMethods.WindowStyles dwStyles = NativeMethods.WindowStyles.WS_TABSTOP | NativeMethods.WindowStyles.WS_VISIBLE | NativeMethods.WindowStyles.WS_CHILD;

        public static bool FrameshiftVal, RandomizeVal, IncrementVal, DecrementVal;
        public static string ControlType;
        public static bool IsWaitingForInput = false;
        public static string InputString = null;
        public static bool HasPressedKey = false;

        public static Brush ProgressBarGreen;
        public static Brush ProgressBarRed = new SolidColorBrush(Color.FromRgb(218, 38, 38));

        public static List<ThreadWindow> ThreadWindows = new List<ThreadWindow>();
        public static byte[] FileBytecode;
        public static bool HasSelectedFile = false;
        public static Dictionary<string, IntPtr> DLL_String_Locations = new Dictionary<string, IntPtr>();
        public MainWindow()
        {
            InitializeComponent();
            CurrentInstance = this;
            Frameshift.IsChecked = true;
            color_dlg.AnyColor = true;
            ProgressBarGreen = CorruptionProgress.Foreground;
        }

        public static void CheckProcess()
        {
            while (!SelectedProcess.HasExited) { }

            foreach (ThreadWindow thread_window in ThreadWindows)
            {
                thread_window.Dispatcher.Invoke(() => thread_window.Close());
            }

            IsPaused = true;
            HasStartedCorruption = false;
            IsDrawing = false;
            Application.Current.Dispatcher.Invoke(() => { Error err = new Error("The process has exited."); err.Show(); });
            CurrentInstance.Dispatcher.Invoke(() =>
            {
                CurrentInstance.ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                CurrentInstance.ToggleDraw.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                CurrentInstance.CurrentProcess.Text = "None";
                CurrentInstance.ProcessIcon.Source = null;
                CurrentInstance.ModuleList.Items.Clear();
                CurrentInstance.ThreadList.Items.Clear();
            });
            SelectedProcess.Close();
            SelectedProcess = null;
        }

        public static void Corrupt_On_Thread(object parameter) // object[]
        {
            object[] parameters = (object[])parameter;
            long base_addr = (long)parameters[0];
            long end_addr = (long)parameters[1];
            Corrupt(base_addr, end_addr);
        }

        public static void Corrupt(long BaseAddress, long EndAddress)
        {
            CurrentInstance.CorruptionProgress.Dispatcher.Invoke(() => { CurrentInstance.CorruptionProgress.Value = 0; CurrentInstance.CorruptionProgress.Maximum = EndAddress - BaseAddress; });

            for (long address = BaseAddress; address < EndAddress; address++)
            {
                if (IsPaused)
                {
                    CurrentInstance.OutputView.Dispatcher.Invoke(() =>
                    {
                        CurrentInstance.OutputView.Items.Add(new OutputViewItem() { Address = address.ToString("X"), ByteData = 0, Message = "Paused.", ColorData = Brushes.Yellow });
                    });
                }

                while (IsPaused) { } // Wait until unpause
                if (!HasStartedCorruption)
                {
                    // Check to see if process has exited
                    return;
                }

                // Read process memory
                // ReadProcessMemory almost always succeeds, so no need for error check or printing.
                byte[] output = new byte[1];
                NativeMethods.ReadProcessMemory(SelectedProcess.Handle, (IntPtr)address, output, 1, out IntPtr unused);

                string appended_text;
                Brush brush;
                long addr_to_write = address;

                CurrentInstance.Frameshift.Dispatcher.Invoke(() =>
                {
                    // Get values
                    FrameshiftVal = CurrentInstance.Frameshift.IsChecked.Value;
                    RandomizeVal = CurrentInstance.Randomize.IsChecked.Value;
                    IncrementVal = CurrentInstance.Increment.IsChecked.Value;
                    DecrementVal = CurrentInstance.Decrement.IsChecked.Value;
                });

                if (FrameshiftVal)
                {
                    addr_to_write = address - 1;
                }
                else if (RandomizeVal)
                {
                    Random random = new Random();
                    output[0] = (byte)random.Next(0, 255);
                }
                else if (IncrementVal)
                {
                    output[0]++;
                }
                else if (DecrementVal)
                {
                    output[0]--;
                }

                bool success_w = NativeMethods.WriteProcessMemory(SelectedProcess.Handle, (IntPtr)addr_to_write, output, 1, out IntPtr unused2);

                if (success_w)
                {
                    appended_text = "Memory Written Successfully";
                    brush = Brushes.Lime;
                }
                else
                {
                    appended_text = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    brush = Brushes.Red;
                }

                CurrentInstance.CorruptionProgress.Dispatcher.Invoke(() => CurrentInstance.CorruptionProgress.Value++);
                CurrentInstance.OutputView.Dispatcher.Invoke(() => {
                    CurrentInstance.OutputView.Items.Add(new OutputViewItem { Address = addr_to_write.ToString("X"), ByteData = output[0], Message = appended_text, ColorData = brush });
                });
            }

            HasStartedCorruption = false;
            CurrentInstance.OutputView.Dispatcher.Invoke(() => {
                CurrentInstance.OutputView.Items.Add(new OutputViewItem() { Address = "", ByteData = 0, Message = "Finished.", ColorData = Brushes.Yellow });
            });

            CurrentInstance.Dispatcher.Invoke(() =>
            {
                CurrentInstance.CorruptionProgress.Foreground = ProgressBarRed;
                CurrentInstance.ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                CurrentInstance.ToggleCorruption.Content = "▶";
            });
        }

        public static IEnumerable<Enum> GetFlags(Enum input)
        {
            foreach (Enum value in Enum.GetValues(input.GetType()))
                if (input.HasFlag(value))
                    yield return value;
        }

        public static BitmapImage BitmapToImageSource(System.Drawing.Bitmap bitmap)
        {
            using (MemoryStream memory = new MemoryStream())
            {
                bitmap.Save(memory, System.Drawing.Imaging.ImageFormat.Bmp);
                memory.Position = 0;
                BitmapImage bitmapimage = new BitmapImage();
                bitmapimage.BeginInit();
                bitmapimage.StreamSource = memory;
                bitmapimage.CacheOption = BitmapCacheOption.OnLoad;
                bitmapimage.EndInit();

                return bitmapimage;
            }
        }

        public static int ColorToRGB(Color crColor)
        {
            return crColor.B << 16 | crColor.G << 8 | crColor.R;
        }

        public static void StartDraw()
        {
            while (IsDrawing)
            {
                NativeMethods.GetCursorPos(out NativeMethods.POINT p);
                IntPtr hdc = NativeMethods.GetDC(SelectedProcess.MainWindowHandle);
                NativeMethods.ScreenToClient(SelectedProcess.MainWindowHandle, ref p);
                NativeMethods.SetPixel(hdc, p.X, p.Y, (uint)ColorToRGB(ColorPaint));
            }
        }

        private void ToggleDraw_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            IsDrawing = !IsDrawing;
            if (IsDrawing)
            {
                ToggleDraw.Background = new SolidColorBrush(Color.FromRgb(255, 150, 150));
                ToggleDraw.Content = "◼";

                if (SelectedProcess.MainWindowHandle == IntPtr.Zero)
                {
                    Error err = new Error("The selected process does not have a defined window.");
                    err.Show();
                    return;
                }
                else
                {
                    Thread th = new Thread(StartDraw);
                    th.Start();
                }
            }
            else
            {
                ToggleDraw.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                ToggleDraw.Content = "▶";
            }
        }

        private void CurrentColor_Click(object sender, RoutedEventArgs e)
        {
            color_dlg.ShowDialog();
            ColorPaint = Color.FromArgb(color_dlg.Color.A, color_dlg.Color.R, color_dlg.Color.G, color_dlg.Color.B);
            CurrentColor.Background = new SolidColorBrush(ColorPaint);
        }

        private void SelectDLL_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.OpenFileDialog Dialog = new System.Windows.Forms.OpenFileDialog
            {
                Multiselect = true,
                Filter = "Dynamic Linked Libraries (*.dll)|*.dll"
            };
            System.Windows.Forms.DialogResult result = Dialog.ShowDialog();

            switch (result)
            {
                case System.Windows.Forms.DialogResult.OK:
                    foreach (string file in Dialog.FileNames)
                    {
                        DLLFiles.Items.Add(file);
                    }
                    break;
                case System.Windows.Forms.DialogResult.Cancel:
                    break;
            }
        }

        private void ResetList_Click(object sender, RoutedEventArgs e)
        {
            DLLFiles.Items.Clear();
        }

        private void RemoveDLL_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                DLLFiles.Items.RemoveAt(DLLFiles.SelectedIndex);
            }
            catch (ArgumentOutOfRangeException)
            {
                Error err = new Error("No files have been selected from the list.");
                err.Show();
            }
        }

        private void InjectDLL_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            foreach (string files in DLLFiles.Items)
            {
                // Allocate memory
                IntPtr address = NativeMethods.VirtualAllocEx(SelectedProcess.Handle, IntPtr.Zero, (uint)(files.Length + 1), NativeMethods.AllocationType.Commit, NativeMethods.MemoryProtection.ExecuteReadWrite);
                // Write in memory
                if (address != IntPtr.Zero)
                {
                    bool success = NativeMethods.WriteProcessMemory(SelectedProcess.Handle, address, Encoding.ASCII.GetBytes(files), files.Length + 1, out IntPtr lpNumberOfBytesWritten);
                    if (success)
                    {
                        IntPtr module = NativeMethods.LoadLibrary("kernel32.dll");
                        IntPtr LoadLib = NativeMethods.GetProcAddress(module, "LoadLibraryA");
                        IntPtr thread_handle = NativeMethods.CreateRemoteThread(SelectedProcess.Handle, IntPtr.Zero, 0, LoadLib, address, 0, out IntPtr lpThreadId);
                        string text;
                        Brush brush;
                        if (thread_handle == IntPtr.Zero)
                        {
                            text = files + " Injection Failed: " + new Win32Exception(Marshal.GetLastWin32Error()).Message;
                            brush = Brushes.Red;
                        }
                        else
                        {
                            NativeMethods.GetExitCodeThread(thread_handle, out ulong module_address);
                            text = files + " Injected Successfully.";
                            brush = Brushes.LimeGreen;
                            DLL_String_Locations.Add(files, (IntPtr)module_address);
                        }

                        OutputView.Items.Add(new OutputViewItem() { Address = address.ToString("X"), ByteData = 0, Message = text, ColorData = brush });
                    }
                    else
                    {
                        Error err = new Error(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        err.Show();
                    }
                }
                else
                {
                    Error err = new Error(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    err.Show();
                }
            }

            LoadModules();
        }

        private void ReloadModules_Click(object sender, RoutedEventArgs e)
        {
            LoadModules();
        }

        private void InjectFunction_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error error = new Error("No processes have been selected.");
                error.Show();
                return;
            }

            foreach (ProcessModule process_module in SelectedProcess.Modules)
            {
                IntPtr Library = NativeMethods.LoadLibraryEx(process_module.FileName, IntPtr.Zero, NativeMethods.LoadLibraryFlags.DONT_RESOLVE_DLL_REFERENCES);
                IntPtr ProcAddress = NativeMethods.GetProcAddress(Library, Function.Text);
                if (ProcAddress != IntPtr.Zero)
                {
                    if (IsInteger.IsChecked.Value)
                    {
                        if (long.TryParse(FunctionParameter.Text, out long result))
                        {
                            IntPtr th_handle = NativeMethods.CreateRemoteThread(SelectedProcess.Handle, IntPtr.Zero, 0, ProcAddress, (IntPtr)result, 0, out IntPtr unused);
                            OutputView.Items.Add(new OutputViewItem() { Address = ProcAddress.ToString("X"), ByteData = 0, ColorData = Brushes.Lime, Message = "'" + Function.Text + "(" + result.ToString("X") + ")' evaluated successfully." });
                        }
                        else
                        {
                            Error error = new Error("\"" + FunctionParameter.Text + "\" is not a valid numerical value.");
                            error.Show();
                            return;
                        }
                    }
                    else
                    {
                        IntPtr base_addr = NativeMethods.VirtualAllocEx(SelectedProcess.Handle, IntPtr.Zero, (uint)FunctionParameter.Text.Length + 1, NativeMethods.AllocationType.Commit, NativeMethods.MemoryProtection.ExecuteReadWrite);
                        NativeMethods.WriteProcessMemory(SelectedProcess.Handle, base_addr, Encoding.ASCII.GetBytes(FunctionParameter.Text), FunctionParameter.Text.Length + 1, out IntPtr unused);

                        NativeMethods.CreateRemoteThread(SelectedProcess.Handle, IntPtr.Zero, 0, ProcAddress, base_addr, 0, out IntPtr unused2);
                        OutputView.Items.Add(new OutputViewItem() { Address = ProcAddress.ToString("X"), ByteData = 0, ColorData = Brushes.Lime, Message = "'" + Function.Text + "(" + FunctionParameter.Text + ")' evaluated successfully." });
                    }
                    return;
                }
            }

            Error err = new Error("The function \"" + Function.Text + "\" could not be found or an extraneous error occurred.");
            err.Show();
        }

        public void ReloadThreads(Process process)
        {
            ThreadList.Items.Clear();
            foreach (ProcessThread thread in process.Threads)
            {
                ThreadList.Items.Add(new ThreadItem() { Id = thread.Id, StartAddress = thread.StartAddress.ToString("X"), State = thread.ThreadState, TimeStarted = thread.StartTime });
            }
        }

        private void ReloadThreadsButton_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            SelectedProcess = Process.GetProcessById(SelectedProcess.Id);
            ReloadThreads(SelectedProcess);
        }

        private void Properties_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            if (ThreadList.SelectedItem == null)
            {
                Error err = new Error("No threads were selected.");
                err.Show();
                return;
            }

            List<int> Ids = new List<int>();
            foreach (ProcessThread module in Process.GetProcessById(SelectedProcess.Id).Threads)
            {
                Ids.Add(module.Id);
            }

            if (!Ids.Contains(((ThreadItem)ThreadList.SelectedItem).Id))
            {
                Error err = new Error("The requested thread could not be found.");
                err.Show();
                return;
            }

            ThreadWindow tw = new ThreadWindow(((ThreadItem)ThreadList.SelectedItem).Id);
            tw.Show();
            ThreadWindows.Add(tw);
        }

        private void KillProcess_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }
            SelectedProcess.Kill();
        }

        private void InjectControl_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            SelectedProcess = Process.GetProcessById(SelectedProcess.Id);
            if (SelectedProcess.MainWindowHandle == IntPtr.Zero)
            {
                Error err = new Error("The selected process does not have a window.");
                err.Show();
                return;
            }
            else
            {
                if (ControlType == string.Empty)
                {
                    Error err = new Error("No control type was selected.");
                    err.Show();
                    return;
                }

                int x, y, width, height;
                if (!int.TryParse(ControlX.Text, out x))
                {
                    Error err = new Error("The X Value must be a valid integer value.");
                    err.Show();
                    return;
                }

                if (!int.TryParse(ControlY.Text, out y))
                {
                    Error err = new Error("The Y Value must be a valid integer value.");
                    err.Show();
                    return;
                }

                if (!int.TryParse(ControlWidth.Text, out width))
                {
                    Error err = new Error("The Width Value must be a valid integer value.");
                    err.Show();
                    return;
                }

                if (!int.TryParse(ControlHeight.Text, out height))
                {
                    Error err = new Error("The Height Value must be a valid integer value.");
                    err.Show();
                    return;
                }

                IntPtr handle = NativeMethods.CreateWindowExA(0, ((ComboBoxItem)ControlTypes.SelectedItem).Tag.ToString(), ControlText.Text, dwStyles, x, y, width, height, SelectedProcess.MainWindowHandle, IntPtr.Zero, NativeMethods.GetWindowLong(SelectedProcess.MainWindowHandle, -6), IntPtr.Zero);

                if (handle == IntPtr.Zero)
                {
                    Error err = new Error("An error occured: " + new Win32Exception(Marshal.GetLastWin32Error()));
                    err.Show();
                    return;
                }
                NativeMethods.SetParent(handle, SelectedProcess.MainWindowHandle);
            }
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            if (SelectedProcess != null)
            {
                SelectedProcess.Close();
            }

            Proc_check.Abort(); // Make sure no threads are left
            Closing -= Window_Closing;
            e.Cancel = true;
            var anim = new DoubleAnimation(0, TimeSpan.FromSeconds(0.25));
            anim.Completed += (s, _) => Close();
            BeginAnimation(OpacityProperty, anim);
        }

        private void CurrentProcess_MouseDown(object sender, MouseButtonEventArgs e)
        {
            ProcessSelector proc_select = new ProcessSelector();
            proc_select.Show();
        }

        private void Grid_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            DragMove();
        }

        private void CloseButton_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Window_Closing(null, new CancelEventArgs());
        }

        private void MinimizeButton_MouseDown(object sender, MouseButtonEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void HelpButton_MouseDown(object sender, MouseButtonEventArgs e)
        {
            About msg = new About();
            msg.Show();
        }

        public void TextBox_IntegerChecker(object sender, TextChangedEventArgs e)
        {
            if (!int.TryParse(((TextBox)sender).Text, out int unused))
            {
                ((TextBox)sender).Foreground = Brushes.Red;
            }
            else
            {
                ((TextBox)sender).Foreground = Brushes.Black;
            }
        }

        public void TextBox_HexidecimalChecker(object sender, TextChangedEventArgs e)
        {
            if (!long.TryParse(((TextBox)sender).Text, System.Globalization.NumberStyles.HexNumber, null, out long unused))
            {
                ((TextBox)sender).Foreground = Brushes.Red;
            }
            else
            {
                ((TextBox)sender).Foreground = Brushes.Black;
            }
        }

        private void AllocateMemory_Checked(object sender, RoutedEventArgs e)
        {
            BytecodeBaseAddress.IsEnabled = false;
        }

        private void AllocateMemory_Unchecked(object sender, RoutedEventArgs e)
        {
            BytecodeBaseAddress.IsEnabled = true;
        }

        private void OpenBytecode_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.OpenFileDialog file_dialog = new System.Windows.Forms.OpenFileDialog();
            file_dialog.Filter = "Binary Files (*.bin)|*.bin|All Files (*.*)|*.*";
            file_dialog.Multiselect = false;
            System.Windows.Forms.DialogResult result = file_dialog.ShowDialog();

            if (result == System.Windows.Forms.DialogResult.OK)
            {
                OutputView.Items.Add(new OutputViewItem() { ByteData = 0, ColorData = Brushes.Magenta, Message = "Loaded \"" + file_dialog.FileName + "\"" });
                FileBytecode = File.ReadAllBytes(file_dialog.FileName);
                HasSelectedFile = true;
            }
        }

        private void InjectBytecode_Click(object sender, RoutedEventArgs e)
        {
            long result;
            bool success_w;
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            if (!HasSelectedFile)
            {
                Error err = new Error("No files have been selected.");
                err.Show();
                return;
            }
            if (AllocateMemory.IsChecked.Value)
            {
                IntPtr address = NativeMethods.VirtualAllocEx(SelectedProcess.Handle, IntPtr.Zero, (uint)FileBytecode.Length, NativeMethods.AllocationType.Commit, NativeMethods.MemoryProtection.ExecuteReadWrite);
                if (address == IntPtr.Zero)
                {
                    Error err = new Error(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    err.Show();
                    return;
                }
                else
                {
                    result = (long)address;
                    success_w = NativeMethods.WriteProcessMemory(SelectedProcess.Handle, address, FileBytecode, FileBytecode.Length, out IntPtr unused);
                }
            }
            else
            {
                if (!long.TryParse(BytecodeBaseAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out result))
                {
                    Error err = new Error("The Base Address must be a Hexidecimal value.");
                    err.Show();
                    return;
                }
                else
                {
                    success_w = NativeMethods.WriteProcessMemory(SelectedProcess.Handle, (IntPtr)result, FileBytecode, FileBytecode.Length, out IntPtr unused);
                }
            }

            OutputViewItem output = new OutputViewItem() { Address = result.ToString("X"), ByteData = FileBytecode[0] };

            if (success_w)
            {
                output.Message = "Memory Written Successfully";
                output.ColorData = Brushes.Lime;
            }
            else
            {
                output.Message = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                output.ColorData = Brushes.Red;
            }

            OutputView.Items.Add(output);
        }

        private void SaveBytecode_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            if (!long.TryParse(BytecodeBaseAddress1.Text, System.Globalization.NumberStyles.HexNumber, null, out long result_base))
            {
                Error err = new Error("\"" + BytecodeBaseAddress1.Text + "\" is not a valid Memory Address.");
                err.Show();
                return;
            }

            if (!long.TryParse(BytecodeEndAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out long result_end))
            {
                Error err = new Error("\"" + BytecodeEndAddress.Text + "\" is not a valid Memory Address.");
                err.Show();
                return;
            }

            System.Windows.Forms.SaveFileDialog fileDialog = new System.Windows.Forms.SaveFileDialog();
            fileDialog.Filter = "Binary Files (*.bin)|*.bin|All Files (*.*)|*.*";
            System.Windows.Forms.DialogResult result = fileDialog.ShowDialog();
                
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                List<byte> byte_list = new List<byte>();
                byte[] byte_array = new byte[1];
                for (long address = result_base; address <= result_end; address++)
                {
                    NativeMethods.ReadProcessMemory(SelectedProcess.Handle, (IntPtr)address, byte_array, 1, out IntPtr unused1);
                    byte_list.Add(byte_array[0]);
                }
                byte[] bytes = byte_list.ToArray();
                File.WriteAllBytes(fileDialog.FileName, bytes);
            }
        }

        private void UnloadDLL_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            if (DLLFiles.SelectedIndex == -1)
            {
                Error err = new Error("No files were selected from the list.");
                err.Show();
                return;
            }

            foreach (string files in DLLFiles.SelectedItems)
            {
                try
                {
                    IntPtr module = NativeMethods.LoadLibrary("kernel32.dll");
                    IntPtr FreeLib = NativeMethods.GetProcAddress(module, "FreeLibrary");
                    IntPtr thread_handle = NativeMethods.CreateRemoteThread(SelectedProcess.Handle, IntPtr.Zero, 0, FreeLib, DLL_String_Locations[files], 0, out IntPtr unused);
                    LoadModules();
                }
                catch (KeyNotFoundException)
                {
                    Error err = new Error("The File String Cannot be Found in the Process.");
                    err.Show();
                    return;
                }
            }
        }

        public void LoadModules()
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            // Activate Spinning Cursor to let user know that the list is loading
            System.Windows.Forms.Cursor.Current = System.Windows.Forms.Cursors.WaitCursor;
            SelectedProcess = Process.GetProcessById(SelectedProcess.Id); // Reloads module list
            ModuleList.Items.Clear();

            if (SelectedProcess.HasExited)
            {
                Error err = new Error("The process has exited.");
                return;
            }

            foreach (ProcessModule module in SelectedProcess.Modules)
            {
                PeHeaderReader reader = new PeHeaderReader(module.FileName);
                TreeViewItem section_nodes = new TreeViewItem { Header = module.ModuleName };
                TreeViewItem ModuleInfo_x86 = new TreeViewItem { Header = "x86 Information" };
                TreeViewItem ModuleInfo_x64 = new TreeViewItem { Header = "x64 Information" };
                TreeViewItem BaseAddressTemplate = new TreeViewItem { Header = "Base Address" };
                TreeViewItem EndAddressTemplate = new TreeViewItem { Header = "End Address" };
                TreeViewItem ByteSizeTemplate = new TreeViewItem { Header = "Byte Size" };

                if (reader.Is32BitHeader)
                {
                    // Add x86 Module Information
                    TreeViewItem AddressOfEntryPoint = new TreeViewItem { Header = "Entry Point Address" };
                    AddressOfEntryPoint.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.AddressOfEntryPoint).ToString("X") });

                    TreeViewItem Architecture = new TreeViewItem { Header = "Architecture" };
                    TreeViewItem ArchitectureBaseAddress = BaseAddressTemplate;
                    TreeViewItem ArchitectureEndAddress = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ArchitectureSize = new TreeViewItem { Header = "Size of Architecture" };
                    ArchitectureBaseAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.Architecture.VirtualAddress).ToString("X") });
                    ArchitectureEndAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.Architecture.VirtualAddress + reader.OptionalHeader32.Architecture.Size - 1).ToString("X") });
                    ArchitectureSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.Architecture.Size.ToString() + " Bytes" });
                    Architecture.Items.Add(ArchitectureBaseAddress);
                    Architecture.Items.Add(ArchitectureEndAddress);
                    Architecture.Items.Add(ArchitectureSize);

                    TreeViewItem Code = new TreeViewItem { Header = "Code" };
                    TreeViewItem BaseOfCode = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem EndOfCode = new TreeViewItem { Header = "End Address" };
                    TreeViewItem SizeOfCode = new TreeViewItem { Header = "Byte Size" };
                    BaseOfCode.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.BaseOfCode).ToString("X") });
                    EndOfCode.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.BaseOfCode + reader.OptionalHeader32.SizeOfCode - 1).ToString("X") });
                    SizeOfCode.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfCode.ToString() + " Bytes" });
                    Code.Items.Add(BaseOfCode);
                    Code.Items.Add(EndOfCode);
                    Code.Items.Add(SizeOfCode);

                    TreeViewItem Data = new TreeViewItem { Header = "Data" };
                    TreeViewItem BaseOfData = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem EndOfInitializedData = new TreeViewItem { Header = "End Address of Initialized Data" };
                    TreeViewItem EndOfUninitializedData = new TreeViewItem { Header = "End Address of Uninitialized Data" };
                    TreeViewItem SizeOfInitializedData = new TreeViewItem { Header = "Size of Initialized Data" };
                    TreeViewItem SizeOFUninitializedData = new TreeViewItem { Header = "Size of Uninitialized Data" };
                    BaseOfData.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.BaseOfData).ToString("X") });
                    EndOfInitializedData.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.SizeOfInitializedData + reader.OptionalHeader32.BaseOfData - 1).ToString("X") });
                    EndOfUninitializedData.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.SizeOfUninitializedData + reader.OptionalHeader32.BaseOfData - 1).ToString("X") });
                    SizeOfInitializedData.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfInitializedData.ToString() + " Bytes" });
                    SizeOFUninitializedData.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfUninitializedData.ToString() + " Bytes" });
                    Data.Items.Add(BaseOfData);
                    Data.Items.Add(EndOfInitializedData);
                    Data.Items.Add(EndOfUninitializedData);
                    Data.Items.Add(SizeOfInitializedData);
                    Data.Items.Add(SizeOFUninitializedData);

                    TreeViewItem RelocationTable = new TreeViewItem { Header = "Relocation Table" };
                    TreeViewItem BaseRelocationTable = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem EndRelocationTable = new TreeViewItem { Header = "End Address" };
                    TreeViewItem RelocationTableSize = new TreeViewItem { Header = "Byte Size" };
                    BaseRelocationTable.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.BaseRelocationTable.VirtualAddress).ToString("X") });
                    EndRelocationTable.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.BaseRelocationTable.VirtualAddress + reader.OptionalHeader32.BaseRelocationTable.Size - 1).ToString("X") });
                    RelocationTableSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.BaseRelocationTable.Size.ToString() + " Bytes" });
                    RelocationTable.Items.Add(BaseRelocationTable);
                    RelocationTable.Items.Add(EndRelocationTable);
                    RelocationTable.Items.Add(RelocationTableSize);

                    TreeViewItem BoundImport = new TreeViewItem { Header = "Bound Imports" };
                    TreeViewItem BoundImportBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem BoundImportEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem BoundImportSize = new TreeViewItem { Header = "Byte Size" };
                    BoundImportBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.BoundImport.VirtualAddress).ToString("X") });
                    BoundImportEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.BoundImport.VirtualAddress + reader.OptionalHeader32.BoundImport.Size - 1).ToString("X") });
                    BoundImportSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.BoundImport.Size.ToString() + " Bytes" });
                    BoundImport.Items.Add(BoundImportBase);
                    BoundImport.Items.Add(BoundImportEnd);
                    BoundImport.Items.Add(BoundImportSize);

                    TreeViewItem CertificateTable = new TreeViewItem { Header = "Certificate Table" };
                    TreeViewItem CertificateBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem CertificateEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem CertificateSize = new TreeViewItem { Header = "Byte Size" };
                    CertificateBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.CertificateTable.VirtualAddress).ToString("X") });
                    CertificateEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.CertificateTable.VirtualAddress + reader.OptionalHeader32.CertificateTable.Size - 1).ToString("X") });
                    CertificateSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.CertificateTable.Size.ToString() + " Bytes" });
                    CertificateTable.Items.Add(CertificateBase);
                    CertificateTable.Items.Add(CertificateEnd);
                    CertificateTable.Items.Add(CertificateSize);

                    TreeViewItem CheckSum = new TreeViewItem { Header = "Checksum" };
                    CheckSum.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.CheckSum });

                    TreeViewItem CLRRuntimeHeader = new TreeViewItem { Header = "CLR Runtime Header" };
                    TreeViewItem CLRBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem CLREnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem CLRSize = new TreeViewItem { Header = "Byte Size" };
                    CLRBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.CLRRuntimeHeader.VirtualAddress).ToString("X") });
                    CLREnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.CLRRuntimeHeader.VirtualAddress + reader.OptionalHeader32.CLRRuntimeHeader.Size - 1).ToString("X") });
                    CLRSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.CLRRuntimeHeader.Size.ToString() + " Bytes" });
                    CLRRuntimeHeader.Items.Add(CLRBase);
                    CLRRuntimeHeader.Items.Add(CLREnd);
                    CLRRuntimeHeader.Items.Add(CLRSize);

                    TreeViewItem Debug_Data = new TreeViewItem { Header = "Debug" };
                    TreeViewItem DebugBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem DebugEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem DebugSize = new TreeViewItem { Header = "Byte Size" };
                    DebugBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.Debug.VirtualAddress).ToString("X") });
                    DebugEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.Debug.VirtualAddress + reader.OptionalHeader32.Debug.Size - 1).ToString("X") });
                    DebugSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.Debug.Size.ToString() + " Bytes" });
                    Debug_Data.Items.Add(DebugBase);
                    Debug_Data.Items.Add(DebugEnd);
                    Debug_Data.Items.Add(DebugSize);

                    TreeViewItem DelayImportDescriptor = new TreeViewItem { Header = "Delay Import Descriptor" };
                    TreeViewItem DelayBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem DelayEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem DelaySize = new TreeViewItem { Header = "Byte Size" };
                    DelayBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.DelayImportDescriptor.VirtualAddress).ToString("X") });
                    DelayEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.DelayImportDescriptor.VirtualAddress + reader.OptionalHeader32.DelayImportDescriptor.Size - 1).ToString("X") });
                    DelaySize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.DelayImportDescriptor.Size.ToString() + " Bytes" });
                    DelayImportDescriptor.Items.Add(DelayBase);
                    DelayImportDescriptor.Items.Add(DelayEnd);
                    DelayImportDescriptor.Items.Add(DelaySize);

                    TreeViewItem ExceptionTable = new TreeViewItem { Header = "Exception Table" };
                    TreeViewItem ExceptionBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ExceptionEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ExceptionSize = new TreeViewItem { Header = "Byte Size" };
                    ExceptionBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ExceptionTable.VirtualAddress).ToString("X") });
                    ExceptionEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ExceptionTable.VirtualAddress + reader.OptionalHeader32.ExceptionTable.Size - 1).ToString("X") });
                    ExceptionSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.ExceptionTable.Size.ToString() + " Bytes" });
                    ExceptionTable.Items.Add(ExceptionBase);
                    ExceptionTable.Items.Add(ExceptionEnd);
                    ExceptionTable.Items.Add(ExceptionSize);

                    TreeViewItem ExportTable = new TreeViewItem { Header = "Export Table" };
                    TreeViewItem ExportBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ExportEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ExportSize = new TreeViewItem { Header = "Byte Size" };
                    ExportBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ExportTable.VirtualAddress).ToString("X") });
                    ExportEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ExportTable.VirtualAddress + reader.OptionalHeader32.ExportTable.Size - 1).ToString("X") });
                    ExportSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.ExportTable.Size + " Bytes" });
                    ExportTable.Items.Add(ExportBase);
                    ExportTable.Items.Add(ExportEnd);
                    ExportTable.Items.Add(ExportSize);

                    TreeViewItem GlobalPointer = new TreeViewItem { Header = "Global Pointer" };
                    TreeViewItem GlobalBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem GlobalEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem GlobalSize = new TreeViewItem { Header = "Byte Size" };
                    GlobalBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.GlobalPtr.VirtualAddress).ToString("X") });
                    GlobalEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.GlobalPtr.VirtualAddress + reader.OptionalHeader32.GlobalPtr.Size - 1).ToString("X") });
                    GlobalSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.ExportTable.Size + " Bytes" });
                    GlobalPointer.Items.Add(GlobalBase);
                    GlobalPointer.Items.Add(GlobalEnd);
                    GlobalPointer.Items.Add(GlobalSize);

                    TreeViewItem Heap = new TreeViewItem { Header = "Heap" };
                    TreeViewItem HeapCommit = new TreeViewItem { Header = "Committed Bytes" };
                    TreeViewItem HeapReserved = new TreeViewItem { Header = "Reserved Bytes" };
                    HeapCommit.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfHeapCommit.ToString() + " Bytes" });
                    HeapReserved.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfHeapReserve.ToString() + " Bytes" });
                    Heap.Items.Add(HeapCommit);
                    Heap.Items.Add(HeapReserved);

                    TreeViewItem IAT = new TreeViewItem { Header = "IAT Data" };
                    TreeViewItem IATBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem IATEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem IATSize = new TreeViewItem { Header = "Byte Size" };
                    IATBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.IAT.VirtualAddress).ToString("X") });
                    IATEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.IAT.VirtualAddress + reader.OptionalHeader32.IAT.Size - 1).ToString("X") });
                    IATSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.IAT.Size.ToString() + " Bytes" });
                    IAT.Items.Add(IATBase);
                    IAT.Items.Add(IATEnd);
                    IAT.Items.Add(IATSize);

                    TreeViewItem ImportTable = new TreeViewItem { Header = "Import Table" };
                    TreeViewItem ImportBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ImportEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ImportSize = new TreeViewItem { Header = "Byte Size" };
                    ImportBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ImportTable.VirtualAddress).ToString("X") });
                    ImportEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ImportTable.VirtualAddress + reader.OptionalHeader32.ImportTable.Size - 1).ToString("X") });
                    ImportSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.ImportTable.Size.ToString() + " Bytes" });
                    ImportTable.Items.Add(ImportBase);
                    ImportTable.Items.Add(ImportEnd);
                    ImportTable.Items.Add(ImportSize);

                    TreeViewItem Image_Data = new TreeViewItem { Header = "Image Data" };
                    TreeViewItem ImageBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ImageEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ImageSize = new TreeViewItem { Header = "Byte Size" };
                    ImageBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ImageBase).ToString("X") });
                    ImageEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ImageBase + reader.OptionalHeader32.SizeOfImage - 1).ToString("X") });
                    ImageSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfImage.ToString() + " Bytes" });
                    Image_Data.Items.Add(ImageBase);
                    Image_Data.Items.Add(ImageEnd);
                    Image_Data.Items.Add(ImageSize);

                    TreeViewItem LoadConfigTable = new TreeViewItem { Header = "Load Config Table" };
                    TreeViewItem ConfigBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ConfigEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ConfigSize = new TreeViewItem { Header = "Byte Size" };
                    ConfigBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.LoadConfigTable.VirtualAddress).ToString("X") });
                    ConfigEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.LoadConfigTable.VirtualAddress + reader.OptionalHeader32.LoadConfigTable.Size - 1).ToString("X") });
                    ConfigSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.LoadConfigTable.Size.ToString() + " Bytes" });
                    LoadConfigTable.Items.Add(ConfigBase);
                    LoadConfigTable.Items.Add(ConfigEnd);
                    LoadConfigTable.Items.Add(ConfigSize);

                    TreeViewItem Stack_Data = new TreeViewItem { Header = "Stack" };
                    TreeViewItem StackCommit = new TreeViewItem { Header = "Committed Bytes" };
                    TreeViewItem StackReserve = new TreeViewItem { Header = "Reserved Bytes" };
                    StackCommit.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfStackCommit.ToString() + " Bytes" });
                    StackReserve.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.SizeOfStackReserve.ToString() + " Bytes" });
                    Stack_Data.Items.Add(StackCommit);
                    Stack_Data.Items.Add(StackReserve);

                    TreeViewItem TLSTable = new TreeViewItem { Header = "TLS Table" };
                    TreeViewItem TLSBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem TLSEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem TLSSize = new TreeViewItem { Header = "Byte Size" };
                    TLSBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.TLSTable.VirtualAddress).ToString("X") });
                    TLSEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.TLSTable.VirtualAddress + reader.OptionalHeader32.TLSTable.Size - 1).ToString("X") });
                    TLSSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.TLSTable.Size.ToString() + " Bytes" });
                    TLSTable.Items.Add(TLSBase);
                    TLSTable.Items.Add(TLSEnd);
                    TLSTable.Items.Add(TLSSize);

                    TreeViewItem Reserved = new TreeViewItem { Header = "Reserved Data" };
                    TreeViewItem ReservedBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ReservedEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ReservedSize = new TreeViewItem { Header = "Byte Size" };
                    ReservedBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.Reserved.VirtualAddress).ToString("X") });
                    ReservedEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.Reserved.VirtualAddress + reader.OptionalHeader32.Reserved.Size - 1).ToString("X") });
                    ReservedSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.Reserved.Size.ToString() + " Bytes" });
                    Reserved.Items.Add(ReservedBase);
                    Reserved.Items.Add(ReservedEnd);
                    Reserved.Items.Add(ReservedSize);

                    TreeViewItem ResourceTable = new TreeViewItem { Header = "Resource Table" };
                    TreeViewItem ResourceBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ResourceEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ResourceSize = new TreeViewItem { Header = "Byte Size" };
                    ResourceBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ResourceTable.VirtualAddress).ToString("X") });
                    ResourceEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader32.ResourceTable.VirtualAddress + reader.OptionalHeader32.ResourceTable.Size - 1).ToString("X") });
                    ResourceSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader32.ResourceTable.Size.ToString() + " Bytes" });
                    ResourceTable.Items.Add(ResourceBase);
                    ResourceTable.Items.Add(ResourceEnd);
                    ResourceTable.Items.Add(ResourceSize);

                    // Add them all together
                    ModuleInfo_x86.Items.Add(AddressOfEntryPoint);
                    ModuleInfo_x86.Items.Add(Code);
                    ModuleInfo_x86.Items.Add(Data);
                    ModuleInfo_x86.Items.Add(RelocationTable);
                    ModuleInfo_x86.Items.Add(BoundImport);
                    ModuleInfo_x86.Items.Add(CertificateTable);
                    ModuleInfo_x86.Items.Add(CheckSum);
                    ModuleInfo_x86.Items.Add(CLRRuntimeHeader);
                    ModuleInfo_x86.Items.Add(Debug_Data);
                    ModuleInfo_x86.Items.Add(DelayImportDescriptor);
                    ModuleInfo_x86.Items.Add(ExceptionTable);
                    ModuleInfo_x86.Items.Add(ExportTable);
                    ModuleInfo_x86.Items.Add(GlobalPointer);
                    ModuleInfo_x86.Items.Add(Heap);
                    ModuleInfo_x86.Items.Add(IAT);
                    ModuleInfo_x86.Items.Add(ImportTable);
                    ModuleInfo_x86.Items.Add(Image_Data);
                    ModuleInfo_x86.Items.Add(LoadConfigTable);
                    ModuleInfo_x86.Items.Add(Stack_Data);
                    ModuleInfo_x86.Items.Add(TLSTable);
                    ModuleInfo_x86.Items.Add(Reserved);
                    ModuleInfo_x86.Items.Add(ResourceTable);
                }
                else
                {
                    // Add x64 Module Data
                    TreeViewItem AddressOfEntryPoint = new TreeViewItem { Header = "Entry Point Address" };
                    AddressOfEntryPoint.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.AddressOfEntryPoint).ToString("X") });

                    TreeViewItem Architecture = new TreeViewItem { Header = "Architecture" };
                    TreeViewItem ArchitectureBaseAddress = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ArchitectureEndAddress = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ArchitectureSize = new TreeViewItem { Header = "Size Of Architecture" };
                    ArchitectureBaseAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.Architecture.VirtualAddress).ToString("X") });
                    ArchitectureEndAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.Architecture.VirtualAddress + reader.OptionalHeader64.Architecture.Size - 1).ToString("X") });
                    ArchitectureSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.Architecture.Size.ToString() + " Bytes" });
                    Architecture.Items.Add(ArchitectureBaseAddress);
                    Architecture.Items.Add(ArchitectureEndAddress);
                    Architecture.Items.Add(ArchitectureSize);

                    TreeViewItem Code = new TreeViewItem { Header = "Code" };
                    TreeViewItem BaseOfCode = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem EndOfCode = new TreeViewItem { Header = "End Address" };
                    TreeViewItem SizeOfCode = new TreeViewItem { Header = "Byte Size" };
                    BaseOfCode.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.BaseOfCode).ToString("X") });
                    EndOfCode.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.BaseOfCode + reader.OptionalHeader64.SizeOfCode - 1).ToString("X") });
                    SizeOfCode.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfCode.ToString() + " Bytes" });
                    Code.Items.Add(BaseOfCode);
                    Code.Items.Add(EndOfCode);
                    Code.Items.Add(SizeOfCode);

                    TreeViewItem Data = new TreeViewItem { Header = "Data" };
                    TreeViewItem SizeOfInitializedData = new TreeViewItem { Header = "Size of Initialized Data" };
                    TreeViewItem SizeOFUninitializedData = new TreeViewItem { Header = "Size of Uninitialized Data" };
                    SizeOfInitializedData.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfInitializedData.ToString() + " Bytes" });
                    SizeOFUninitializedData.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfUninitializedData.ToString() + " Bytes" });
                    Data.Items.Add(SizeOfInitializedData);
                    Data.Items.Add(SizeOFUninitializedData);

                    TreeViewItem RelocationTable = new TreeViewItem { Header = "Relocation Table" };
                    TreeViewItem BaseRelocationTable = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem EndRelocationTable = new TreeViewItem { Header = "End Address" };
                    TreeViewItem RelocationTableSize = new TreeViewItem { Header = "Byte Size" };
                    BaseRelocationTable.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.BaseRelocationTable.VirtualAddress).ToString("X") });
                    EndRelocationTable.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.BaseRelocationTable.VirtualAddress + reader.OptionalHeader64.BaseRelocationTable.Size - 1).ToString("X") });
                    RelocationTableSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.BaseRelocationTable.Size.ToString() + " Bytes" });
                    RelocationTable.Items.Add(BaseRelocationTable);
                    RelocationTable.Items.Add(EndRelocationTable);
                    RelocationTable.Items.Add(RelocationTableSize);

                    TreeViewItem BoundImport = new TreeViewItem { Header = "Bound Imports" };
                    TreeViewItem BoundImportBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem BoundImportEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem BoundImportSize = new TreeViewItem { Header = "Byte Size" };
                    BoundImportBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.BoundImport.VirtualAddress).ToString("X") });
                    BoundImportEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.BoundImport.VirtualAddress + reader.OptionalHeader64.BoundImport.Size - 1).ToString("X") });
                    BoundImportSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.BoundImport.Size.ToString() + " Bytes" });
                    BoundImport.Items.Add(BoundImportBase);
                    BoundImport.Items.Add(BoundImportEnd);
                    BoundImport.Items.Add(BoundImportSize);

                    TreeViewItem CertificateTable = new TreeViewItem { Header = "Certificate Table" };
                    TreeViewItem CertificateBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem CertificateEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem CertificateSize = new TreeViewItem { Header = "Byte Size" };
                    CertificateBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.CertificateTable.VirtualAddress).ToString("X") });
                    CertificateEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.CertificateTable.VirtualAddress + reader.OptionalHeader64.CertificateTable.Size - 1).ToString("X") });
                    CertificateSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.CertificateTable.Size.ToString() + " Bytes" });
                    CertificateTable.Items.Add(CertificateBase);
                    CertificateTable.Items.Add(CertificateEnd);
                    CertificateTable.Items.Add(CertificateSize);

                    TreeViewItem CheckSum = new TreeViewItem { Header = "Checksum" };
                    CheckSum.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.CheckSum });

                    TreeViewItem CLRRuntimeHeader = new TreeViewItem { Header = "CLR Runtime Header" };
                    TreeViewItem CLRBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem CLREnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem CLRSize = new TreeViewItem { Header = "Byte Size" };
                    CLRBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.CLRRuntimeHeader.VirtualAddress).ToString("X") });
                    CLREnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.CLRRuntimeHeader.VirtualAddress + reader.OptionalHeader64.CLRRuntimeHeader.Size - 1).ToString("X") });
                    CLRSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.CLRRuntimeHeader.Size.ToString() + " Bytes" });
                    CLRRuntimeHeader.Items.Add(CLRBase);
                    CLRRuntimeHeader.Items.Add(CLREnd);
                    CLRRuntimeHeader.Items.Add(CLRSize);

                    TreeViewItem Debug_Data = new TreeViewItem { Header = "Debug" };
                    TreeViewItem DebugBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem DebugEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem DebugSize = new TreeViewItem { Header = "Byte Size" };
                    DebugBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.Debug.VirtualAddress).ToString("X") });
                    DebugEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.Debug.VirtualAddress + reader.OptionalHeader64.Debug.Size - 1).ToString("X") });
                    DebugSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.Debug.Size.ToString() + " Bytes" });
                    Debug_Data.Items.Add(DebugBase);
                    Debug_Data.Items.Add(DebugEnd);
                    Debug_Data.Items.Add(DebugSize);

                    TreeViewItem DelayImportDescriptor = new TreeViewItem { Header = "Delay Import Descriptor" };
                    TreeViewItem DelayBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem DelayEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem DelaySize = new TreeViewItem { Header = "Byte Size" };
                    DelayBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.DelayImportDescriptor.VirtualAddress).ToString("X") });
                    DelayEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.DelayImportDescriptor.VirtualAddress + reader.OptionalHeader64.DelayImportDescriptor.Size - 1).ToString("X") });
                    DelaySize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.DelayImportDescriptor.Size.ToString() + " Bytes" });
                    DelayImportDescriptor.Items.Add(DelayBase);
                    DelayImportDescriptor.Items.Add(DelayEnd);
                    DelayImportDescriptor.Items.Add(DelaySize);

                    TreeViewItem ExceptionTable = new TreeViewItem { Header = "Exception Table" };
                    TreeViewItem ExceptionBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ExceptionEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ExceptionSize = new TreeViewItem { Header = "Byte Size" };
                    ExceptionBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ExceptionTable.VirtualAddress).ToString("X") });
                    ExceptionEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ExceptionTable.VirtualAddress + reader.OptionalHeader64.ExceptionTable.Size - 1).ToString("X") });
                    ExceptionSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.ExceptionTable.Size.ToString() + " Bytes" });
                    ExceptionTable.Items.Add(ExceptionBase);
                    ExceptionTable.Items.Add(ExceptionEnd);
                    ExceptionTable.Items.Add(ExceptionSize);

                    TreeViewItem ExportTable = new TreeViewItem { Header = "Export Table" };
                    TreeViewItem ExportBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ExportEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ExportSize = new TreeViewItem { Header = "Byte Size" };
                    ExportBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ExportTable.VirtualAddress).ToString("X") });
                    ExportEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ExportTable.VirtualAddress + reader.OptionalHeader64.ExportTable.Size - 1).ToString("X") });
                    ExportSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.ExportTable.Size + " Bytes" });
                    ExportTable.Items.Add(ExportBase);
                    ExportTable.Items.Add(ExportEnd);
                    ExportTable.Items.Add(ExportSize);

                    TreeViewItem GlobalPointer = new TreeViewItem { Header = "Global Pointer" };
                    TreeViewItem GlobalBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem GlobalEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem GlobalSize = new TreeViewItem { Header = "Byte Size" };
                    GlobalBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.GlobalPtr.VirtualAddress).ToString("X") });
                    GlobalEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.GlobalPtr.VirtualAddress + reader.OptionalHeader64.GlobalPtr.Size - 1).ToString("X") });
                    GlobalSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.ExportTable.Size + " Bytes" });
                    GlobalPointer.Items.Add(GlobalBase);
                    GlobalPointer.Items.Add(GlobalEnd);
                    GlobalPointer.Items.Add(GlobalSize);

                    TreeViewItem Heap = new TreeViewItem { Header = "Heap" };
                    TreeViewItem HeapCommit = new TreeViewItem { Header = "Committed Bytes" };
                    TreeViewItem HeapReserved = new TreeViewItem { Header = "Reserved Bytes" };
                    HeapCommit.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfHeapCommit.ToString() + " Bytes" });
                    HeapReserved.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfHeapReserve.ToString() + " Bytes" });
                    Heap.Items.Add(HeapCommit);
                    Heap.Items.Add(HeapReserved);

                    TreeViewItem IAT = new TreeViewItem { Header = "IAT Data" };
                    TreeViewItem IATBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem IATEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem IATSize = new TreeViewItem { Header = "Byte Size" };
                    IATBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.IAT.VirtualAddress).ToString("X") });
                    IATEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.IAT.VirtualAddress + reader.OptionalHeader64.IAT.Size - 1).ToString("X") });
                    IATSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.IAT.Size.ToString() + " Bytes" });
                    IAT.Items.Add(IATBase);
                    IAT.Items.Add(IATEnd);
                    IAT.Items.Add(IATSize);

                    TreeViewItem ImportTable = new TreeViewItem { Header = "Import Table" };
                    TreeViewItem ImportBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ImportEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ImportSize = new TreeViewItem { Header = "Byte Size" };
                    ImportBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ImportTable.VirtualAddress).ToString("X") });
                    ImportEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ImportTable.VirtualAddress + reader.OptionalHeader64.ImportTable.Size - 1).ToString("X") });
                    ImportSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.ImportTable.Size.ToString() + " Bytes" });
                    ImportTable.Items.Add(ImportBase);
                    ImportTable.Items.Add(ImportEnd);
                    ImportTable.Items.Add(ImportSize);

                    TreeViewItem Image_Data = new TreeViewItem { Header = "Image Data" };
                    TreeViewItem ImageBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ImageEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ImageSize = new TreeViewItem { Header = "Byte Size" };
                    ImageBase.Items.Add(new TreeViewItem { Header = ((ulong)module.BaseAddress + reader.OptionalHeader64.ImageBase).ToString("X") });
                    ImageEnd.Items.Add(new TreeViewItem { Header = ((ulong)module.BaseAddress + reader.OptionalHeader64.ImageBase + reader.OptionalHeader64.SizeOfImage - 1).ToString("X") });
                    ImageSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfImage.ToString() + " Bytes" });
                    Image_Data.Items.Add(ImageBase);
                    Image_Data.Items.Add(ImageEnd);
                    Image_Data.Items.Add(ImageSize);

                    TreeViewItem LoadConfigTable = new TreeViewItem { Header = "Load Config Table" };
                    TreeViewItem ConfigBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ConfigEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ConfigSize = new TreeViewItem { Header = "Byte Size" };
                    ConfigBase.Items.Add(new TreeViewItem { Header = ((ulong)module.BaseAddress + reader.OptionalHeader64.LoadConfigTable.VirtualAddress).ToString("X") });
                    ConfigEnd.Items.Add(new TreeViewItem { Header = ((ulong)module.BaseAddress + reader.OptionalHeader64.LoadConfigTable.VirtualAddress + reader.OptionalHeader64.LoadConfigTable.Size - 1).ToString("X") });
                    ConfigSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.LoadConfigTable.Size.ToString() + " Bytes" });
                    LoadConfigTable.Items.Add(ConfigBase);
                    LoadConfigTable.Items.Add(ConfigEnd);
                    LoadConfigTable.Items.Add(ConfigSize);

                    TreeViewItem Stack_Data = new TreeViewItem { Header = "Stack" };
                    TreeViewItem StackCommit = new TreeViewItem { Header = "Committed Bytes" };
                    TreeViewItem StackReserve = new TreeViewItem { Header = "Reserved Bytes" };
                    StackCommit.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfStackCommit.ToString() + " Bytes" });
                    StackReserve.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.SizeOfStackReserve.ToString() + " Bytes" });
                    Stack_Data.Items.Add(StackCommit);
                    Stack_Data.Items.Add(StackReserve);

                    TreeViewItem TLSTable = new TreeViewItem { Header = "TLS Table" };
                    TreeViewItem TLSBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem TLSEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem TLSSize = new TreeViewItem { Header = "Byte Size" };
                    TLSBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.TLSTable.VirtualAddress).ToString("X") });
                    TLSEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.TLSTable.VirtualAddress + reader.OptionalHeader64.TLSTable.Size - 1).ToString("X") });
                    TLSSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.TLSTable.Size.ToString() + " Bytes" });
                    TLSTable.Items.Add(TLSBase);
                    TLSTable.Items.Add(TLSEnd);
                    TLSTable.Items.Add(TLSSize);

                    TreeViewItem Reserved = new TreeViewItem { Header = "Reserved Data" };
                    TreeViewItem ReservedBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ReservedEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ReservedSize = new TreeViewItem { Header = "Byte Size" };
                    ReservedBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.Reserved.VirtualAddress).ToString("X") });
                    ReservedEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.Reserved.VirtualAddress + reader.OptionalHeader64.Reserved.Size - 1).ToString("X") });
                    ReservedSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.Reserved.Size.ToString() + " Bytes" });
                    Reserved.Items.Add(ReservedBase);
                    Reserved.Items.Add(ReservedEnd);
                    Reserved.Items.Add(ReservedSize);

                    TreeViewItem ResourceTable = new TreeViewItem { Header = "Resource Table" };
                    TreeViewItem ResourceBase = new TreeViewItem { Header = "Base Address" };
                    TreeViewItem ResourceEnd = new TreeViewItem { Header = "End Address" };
                    TreeViewItem ResourceSize = new TreeViewItem { Header = "Byte Size" };
                    ResourceBase.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ResourceTable.VirtualAddress).ToString("X") });
                    ResourceEnd.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + reader.OptionalHeader64.ResourceTable.VirtualAddress + reader.OptionalHeader64.ResourceTable.Size - 1).ToString("X") });
                    ResourceSize.Items.Add(new TreeViewItem { Header = reader.OptionalHeader64.ResourceTable.Size.ToString() + " Bytes" });
                    ResourceTable.Items.Add(ResourceBase);
                    ResourceTable.Items.Add(ResourceEnd);
                    ResourceTable.Items.Add(ResourceSize);

                    // Add them all together
                    ModuleInfo_x64.Items.Add(AddressOfEntryPoint);
                    ModuleInfo_x64.Items.Add(Code);
                    ModuleInfo_x64.Items.Add(Data);
                    ModuleInfo_x64.Items.Add(RelocationTable);
                    ModuleInfo_x64.Items.Add(BoundImport);
                    ModuleInfo_x64.Items.Add(CertificateTable);
                    ModuleInfo_x64.Items.Add(CheckSum);
                    ModuleInfo_x64.Items.Add(CLRRuntimeHeader);
                    ModuleInfo_x64.Items.Add(Debug_Data);
                    ModuleInfo_x64.Items.Add(DelayImportDescriptor);
                    ModuleInfo_x64.Items.Add(ExceptionTable);
                    ModuleInfo_x64.Items.Add(ExportTable);
                    ModuleInfo_x64.Items.Add(GlobalPointer);
                    ModuleInfo_x64.Items.Add(Heap);
                    ModuleInfo_x64.Items.Add(IAT);
                    ModuleInfo_x64.Items.Add(ImportTable);
                    ModuleInfo_x64.Items.Add(Image_Data);
                    ModuleInfo_x64.Items.Add(LoadConfigTable);
                    ModuleInfo_x64.Items.Add(Stack_Data);
                    ModuleInfo_x64.Items.Add(TLSTable);
                    ModuleInfo_x64.Items.Add(Reserved);
                    ModuleInfo_x64.Items.Add(ResourceTable);
                }

                // Add them altogether
                if (reader.Is32BitHeader)
                {
                    section_nodes.Items.Add(ModuleInfo_x86);
                }
                else
                {
                    section_nodes.Items.Add(ModuleInfo_x64);
                }

                // Add Section Data
                foreach (PeHeaderReader.IMAGE_SECTION_HEADER section in reader.ImageSectionHeaders)
                {
                    // Create Nodes for each property of the section
                    TreeViewItem section_top = new TreeViewItem { Header = section.Section.Replace("\0", string.Empty) };

                    // Base Address Node
                    TreeViewItem BaseAddress = new TreeViewItem() { Header = "Base Address" };
                    BaseAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + section.VirtualAddress).ToString("X") });

                    // End Address Node
                    TreeViewItem EndAddress = new TreeViewItem() { Header = "End Address" };
                    EndAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + section.VirtualAddress + section.VirtualSize - 1).ToString("X") });

                    // Byte Size Node
                    TreeViewItem ByteSize = new TreeViewItem() { Header = "Byte Size" };
                    ByteSize.Items.Add(new TreeViewItem { Header = section.VirtualSize.ToString() + " Bytes" });

                    // Raw Base Address Node
                    TreeViewItem RawBaseAddress = new TreeViewItem() { Header = "Raw Base Address" };
                    RawBaseAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + section.PointerToRawData).ToString("X") });

                    // Raw End Address Node
                    TreeViewItem RawEndAddress = new TreeViewItem() { Header = "Raw End Address" };
                    RawEndAddress.Items.Add(new TreeViewItem { Header = ((long)module.BaseAddress + section.PointerToRawData + section.SizeOfRawData - 1).ToString("X") });

                    // Raw Byte Size Node
                    TreeViewItem RawByteSize = new TreeViewItem() { Header = "Raw Byte Size" };
                    RawByteSize.Items.Add(new TreeViewItem { Header = section.SizeOfRawData.ToString() + " Bytes" });

                    // Data Flags Node
                    TreeViewItem DataFlags = new TreeViewItem() { Header = "Data Flags" };
                    foreach (PeHeaderReader.DataSectionFlags flags in GetFlags(section.Characteristics))
                    {
                        DataFlags.Items.Add(new TreeViewItem { Header = flags.ToString() });
                    }

                    // Add them all together
                    section_top.Items.Add(BaseAddress);
                    section_top.Items.Add(EndAddress);
                    section_top.Items.Add(ByteSize);
                    section_top.Items.Add(RawBaseAddress);
                    section_top.Items.Add(RawEndAddress);
                    section_top.Items.Add(RawByteSize);
                    section_top.Items.Add(DataFlags);
                    section_nodes.Items.Add(section_top);
                }
                ModuleList.Items.Add(section_nodes);
            }

            if (string.IsNullOrWhiteSpace(SelectedProcess.MainWindowTitle))
            {
                CurrentProcess.Text = SelectedProcess.ProcessName;
            }
            else
            {
                CurrentProcess.Text = SelectedProcess.MainWindowTitle;
            }

            ProcessIcon.Source = BitmapToImageSource(System.Drawing.Icon.ExtractAssociatedIcon(SelectedProcess.MainModule.FileName).ToBitmap());

            System.Windows.Forms.Cursor.Current = System.Windows.Forms.Cursors.Default;
        }

        private void StartCorruption_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }

            // TOGGLES CORRUPTION
            IsPaused = !IsPaused;
            long base_addr, end_addr;
            if (!IsPaused)
            {
                CorruptionProgress.Foreground = ProgressBarGreen;
                ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(255, 150, 150));
                ToggleCorruption.Content = "◼";

                if (HasStartedCorruption)
                {
                    return;
                }

                if (!has_selected_process)
                {
                    ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                    ToggleCorruption.Content = "▶";
                    Error err = new Error("Please select a process from the list.");
                    err.Show();
                    return;
                }

                if (!long.TryParse(BaseAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out base_addr))
                {
                    ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                    ToggleCorruption.Content = "▶";
                    Error err = new Error("\"" + BaseAddress.Text + "\" is not a valid Memory Address.");
                    err.Show();
                    return;
                }

                if (!long.TryParse(EndAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out end_addr))
                {
                    ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                    ToggleCorruption.Content = "▶";
                    Error err = new Error("\"" + EndAddress.Text + "\" is not a valid Memory Address.");
                    err.Show();
                    return;
                }

                if (base_addr > end_addr)
                {
                    Error err = new Error("The Base Address cannot be larger than the End Address.");
                    err.Show();
                    ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                    ToggleCorruption.Content = "▶";
                    return;
                }

                Thread CorruptionThread = new Thread(Corrupt_On_Thread);
                object[] parameters = new object[2];
                parameters[0] = base_addr;
                parameters[1] = end_addr;
                CorruptionThread.Start(parameters);
                HasStartedCorruption = true;
            }
            else
            {
                CorruptionProgress.Foreground = ProgressBarRed;
                ToggleCorruption.Background = new SolidColorBrush(Color.FromRgb(150, 255, 150));
                ToggleCorruption.Content = "▶";
            }
        }

        private void MenuItem_Click_1(object sender, RoutedEventArgs e)
        {
            About about_box = new About();
            about_box.Show();
        }
    }
}
