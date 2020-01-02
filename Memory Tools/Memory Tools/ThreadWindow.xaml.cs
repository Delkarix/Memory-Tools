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
using System.Windows.Shapes;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Reflection;
using System.ComponentModel;

namespace Memory_Tools
{
    /// <summary>
    /// Interaction logic for ThreadWindow.xaml
    /// </summary>

    public class RegisterItem
    {
        public string Register { get; set; }
        public string Value { get; set; }
    }

    public partial class ThreadWindow : Window
    {
        public NativeMethods.CONTEXT ThreadContext = new NativeMethods.CONTEXT();
        public NativeMethods.CONTEXT64 ThreadContext64 = new NativeMethods.CONTEXT64();
        public static uint ThreadID;
        public bool IsSuspended = ((ThreadItem)MainWindow.CurrentInstance.ThreadList.SelectedItem).IsSuspended;
        public static ThreadWindow MainInstance;

        public ThreadWindow(int threadId)
        {
            MainInstance = this;
            InitializeComponent();
            TextBox Placeholder = new TextBox();
            if (IsSuspended)
            {
                SuspendThreadButton.Content = "Resume Thread";
            }
            else
            {
                SuspendThreadButton.Content = "Suspend Thread";
            }

            ThreadID = (uint)threadId;
            ThreadContext.ContextFlags = (uint)NativeMethods.CONTEXT_FLAGS.CONTEXT_ALL;
            ThreadContext64.ContextFlags = NativeMethods.CONTEXT_FLAGS.CONTEXT_ALL;

            LoadRegisters();
        }

        public void LoadRegisters()
        {
            IntPtr handle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.THREAD_ALL, false, ThreadID);
            NativeMethods.GetThreadContext(handle, ref ThreadContext);
            NativeMethods.Wow64GetThreadContext(handle, ref ThreadContext64);

            EAX.Text = ThreadContext.Eax.ToString("X");
            EBP.Text = ThreadContext.Ebp.ToString("X");
            EBX.Text = ThreadContext.Ebx.ToString("X");
            ECX.Text = ThreadContext.Ecx.ToString("X");
            EDI.Text = ThreadContext.Edi.ToString("X");
            EDX.Text = ThreadContext.Edx.ToString("X");
            EFlags.Text = ThreadContext.EFlags.ToString("X");
            EIP.Text = ThreadContext.Eip.ToString("X");
            ESI.Text = ThreadContext.Esi.ToString("X");
            ESP.Text = ThreadContext.Esp.ToString("X");
            Dr0_32.Text = ThreadContext.Dr0.ToString("X");
            Dr1_32.Text = ThreadContext.Dr1.ToString("X");
            Dr2_32.Text = ThreadContext.Dr2.ToString("X");
            Dr3_32.Text = ThreadContext.Dr3.ToString("X");
            Dr6_32.Text = ThreadContext.Dr6.ToString("X");
            Dr7_32.Text = ThreadContext.Dr7.ToString("X");
            SegCs_32.Text = ThreadContext.SegCs.ToString("X");
            SegDs_32.Text = ThreadContext.SegDs.ToString("X");
            SegEs_32.Text = ThreadContext.SegEs.ToString("X");
            SegFs_32.Text = ThreadContext.SegFs.ToString("X");
            SegGs_32.Text = ThreadContext.SegGs.ToString("X");
            SegSs_32.Text = ThreadContext.SegSs.ToString("X");
            ControlWord.Text = ThreadContext.FloatSave.ControlWord.ToString("X");
            Cr0NpxState.Text = ThreadContext.FloatSave.Cr0NpxState.ToString("X");
            DataOffset.Text = ThreadContext.FloatSave.DataOffset.ToString("X");
            DataSelector.Text = ThreadContext.FloatSave.DataSelector.ToString("X");
            ErrorOffset.Text = ThreadContext.FloatSave.ErrorOffset.ToString("X");
            ErrorSelector.Text = ThreadContext.FloatSave.ErrorSelector.ToString("X");
            StatusWord.Text = ThreadContext.FloatSave.StatusWord.ToString("X");
            TagWord.Text = ThreadContext.FloatSave.TagWord.ToString("X");

            RAX.Text = ThreadContext64.Rax.ToString("X");
            RBP.Text = ThreadContext64.Rbp.ToString("X");
            RBX.Text = ThreadContext64.Rbx.ToString("X");
            RCX.Text = ThreadContext64.Rcx.ToString("X");
            RDI.Text = ThreadContext64.Rdi.ToString("X");
            RDX.Text = ThreadContext64.Rdx.ToString("X");
            EFlags_64.Text = ThreadContext64.EFlags.ToString("X");
            RIP.Text = ThreadContext64.Rip.ToString("X");
            RSI.Text = ThreadContext64.Rsi.ToString("X");
            RSP.Text = ThreadContext64.Rsp.ToString("X");
            LastBranchFromInstruction.Text = ThreadContext64.LastBranchFromRip.ToString("X");
            LastBranchToInstruction.Text = ThreadContext64.LastBranchToRip.ToString("X");
            LastExceptionFromInstruction.Text = ThreadContext64.LastExceptionFromRip.ToString("X");
            LastExceptionToInstruction.Text = ThreadContext64.LastExceptionToRip.ToString("X");
            DebugControl.Text = ThreadContext64.DebugControl.ToString("X");
            Dr0_64.Text = ThreadContext64.Dr0.ToString("X");
            Dr1_64.Text = ThreadContext64.Dr1.ToString("X");
            Dr2_64.Text = ThreadContext64.Dr2.ToString("X");
            Dr3_64.Text = ThreadContext64.Dr3.ToString("X");
            Dr6_64.Text = ThreadContext64.Dr6.ToString("X");
            Dr7_64.Text = ThreadContext64.Dr7.ToString("X");
            SegCs_64.Text = ThreadContext64.SegCs.ToString("X");
            SegDs_64.Text = ThreadContext64.SegDs.ToString("X");
            SegEs_64.Text = ThreadContext64.SegEs.ToString("X");
            SegFs_64.Text = ThreadContext64.SegFs.ToString("X");
            SegGs_64.Text = ThreadContext64.SegGs.ToString("X");
            SegSs_64.Text = ThreadContext64.SegSs.ToString("X");
            P1Home.Text = ThreadContext64.P1Home.ToString("X");
            P2Home.Text = ThreadContext64.P2Home.ToString("X");
            P3Home.Text = ThreadContext64.P3Home.ToString("X");
            P4Home.Text = ThreadContext64.P4Home.ToString("X");
            P5Home.Text = ThreadContext64.P5Home.ToString("X");
            P6Home.Text = ThreadContext64.P6Home.ToString("X");
            MxCsr.Text = ThreadContext64.MxCsr.ToString("X");
            VectorControl.Text = ThreadContext64.VectorControl.ToString("X");
            R8.Text = ThreadContext64.R8.ToString("X");
            R9.Text = ThreadContext64.R9.ToString("X");
            R10.Text = ThreadContext64.R10.ToString("X");
            R11.Text = ThreadContext64.R11.ToString("X");
            R12.Text = ThreadContext64.R12.ToString("X");
            R13.Text = ThreadContext64.R13.ToString("X");
            R14.Text = ThreadContext64.R14.ToString("X");
            R15.Text = ThreadContext64.R15.ToString("X");
            ControlWord_64.Text = ThreadContext64.DUMMYUNIONNAME.ControlWord.ToString("X");
            DataOffset_64.Text = ThreadContext64.DUMMYUNIONNAME.DataOffset.ToString("X");
            DataSelector_64.Text = ThreadContext64.DUMMYUNIONNAME.DataSelector.ToString("X");
            ErrorOffset_64.Text = ThreadContext64.DUMMYUNIONNAME.ErrorOffset.ToString("X");
            ErrorOPCode.Text = ThreadContext64.DUMMYUNIONNAME.ErrorOpcode.ToString("X");
            ErrorSelector_64.Text = ThreadContext64.DUMMYUNIONNAME.ErrorSelector.ToString("X");
            MxCsr_DUN.Text = ThreadContext64.DUMMYUNIONNAME.MxCsr.ToString("X");
            MxCsr_Mask.Text = ThreadContext64.DUMMYUNIONNAME.MxCsr_Mask.ToString("X");
            StatusWord_64.Text = ThreadContext64.DUMMYUNIONNAME.StatusWord.ToString("X");
            TagWord_64.Text = ThreadContext64.DUMMYUNIONNAME.TagWord.ToString("X");

            NativeMethods.CloseHandle(handle);
        }

        private void TextBoxChangeHandler(object sender, TextChangedEventArgs e)
        {
            if (uint.TryParse(((TextBox)sender).Text, System.Globalization.NumberStyles.HexNumber, null, out uint result))
            {
                ((TextBox)sender).Foreground = Brushes.Black;

                FieldInfo ThreadContextInfo = MainInstance.GetType().GetField("ThreadContext");
                object ThreadContextStruct = ThreadContextInfo.GetValue(MainInstance);

                FieldInfo ItemInfo = ThreadContextStruct.GetType().GetField(((TextBox)sender).Tag.ToString());
                ItemInfo.SetValue(ThreadContextStruct, result);
                ThreadContextInfo.SetValue(MainInstance, ThreadContextStruct);

                IntPtr hThread = NativeMethods.OpenThread(NativeMethods.ThreadAccess.THREAD_ALL, false, ThreadID);
                NativeMethods.SetThreadContext(hThread, ref ThreadContext);
                NativeMethods.CloseHandle(hThread);
            }
            else
            {
                ((TextBox)sender).Foreground = Brushes.Red;
            }
        }

        private void TextBoxChangeHandler64(object sender, TextChangedEventArgs e)
        {
            if (ulong.TryParse(((TextBox)sender).Text, System.Globalization.NumberStyles.HexNumber, null, out ulong result))
            {
                ((TextBox)sender).Foreground = Brushes.Black;

                FieldInfo ThreadContext64Info = MainInstance.GetType().GetField("ThreadContext64");
                object ThreadContextStruct = ThreadContext64Info.GetValue(MainInstance);

                FieldInfo ItemInfo = ThreadContextStruct.GetType().GetField(((TextBox)sender).Tag.ToString());
                ItemInfo.SetValue(ThreadContextStruct, result);
                ThreadContext64Info.SetValue(MainInstance, ThreadContextStruct);

                IntPtr hThread = NativeMethods.OpenThread(NativeMethods.ThreadAccess.THREAD_ALL, false, ThreadID);
                NativeMethods.Wow64SetThreadContext(hThread, ref ThreadContext64);
                NativeMethods.CloseHandle(hThread);
            }
            else
            {
                ((TextBox)sender).Foreground = Brushes.Red;
            }
        }

        private void TextBoxChangeHandlerDUMMYUNIONNAME(object sender, TextChangedEventArgs e)
        {
            if (ulong.TryParse(((TextBox)sender).Text, System.Globalization.NumberStyles.HexNumber, null, out ulong result))
            {
                ((TextBox)sender).Foreground = Brushes.Black;

                FieldInfo ThreadContext64Info = MainInstance.GetType().GetField("ThreadContext64");
                object ThreadContextStruct = ThreadContext64Info.GetValue(MainInstance);

                FieldInfo DUMMYUNIONNAME_Info = ThreadContextStruct.GetType().GetField("DUMMYUNIONNAME");
                object DUMMYUNIONNAME_Struct = DUMMYUNIONNAME_Info.GetValue(ThreadContext64);

                FieldInfo ItemInfo = DUMMYUNIONNAME_Struct.GetType().GetField(((TextBox)sender).Tag.ToString());
                ItemInfo.SetValue(DUMMYUNIONNAME_Struct, result);

                DUMMYUNIONNAME_Info.SetValue(ThreadContextStruct, DUMMYUNIONNAME_Struct);
                ThreadContext64Info.SetValue(MainInstance, ThreadContextStruct);

                IntPtr hThread = NativeMethods.OpenThread(NativeMethods.ThreadAccess.THREAD_ALL, false, ThreadID);
                NativeMethods.Wow64SetThreadContext(hThread, ref ThreadContext64);
                NativeMethods.CloseHandle(hThread);
            }
            else
            {
                ((TextBox)sender).Foreground = Brushes.Red;
            }
        }

        private void SuspendThreadButton_Click(object sender, RoutedEventArgs e)
        {
            IsSuspended = !IsSuspended;

            IntPtr thread = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, ThreadID);
            if (IsSuspended)
            {
                SuspendThreadButton.Content = "Resume Thread";
                NativeMethods.SuspendThread(thread);
            }
            else
            {
                SuspendThreadButton.Content = "Suspend Thread";
                NativeMethods.ResumeThread(thread);
            }
            NativeMethods.CloseHandle(thread);
            ((ThreadItem)MainWindow.CurrentInstance.ThreadList.SelectedItem).IsSuspended = IsSuspended;
        }

        private void Reload_Click(object sender, RoutedEventArgs e)
        {
            LoadRegisters();
        }

        private void AbortThread_Click(object sender, RoutedEventArgs e)
        {
            IntPtr hThread = NativeMethods.OpenThread(NativeMethods.ThreadAccess.THREAD_ALL, false, ThreadID);
            bool success = NativeMethods.TerminateThread(hThread, 0);
            NativeMethods.CloseHandle(hThread);

            if (!success)
            {

                Error err = new Error("Could not terminate the thread: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                err.Show();
                return;
            }

            Close();
        }

        private void CloseButton_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Window_Closing(null, new CancelEventArgs());
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            Closing -= Window_Closing;
            e.Cancel = true;
            var anim = new System.Windows.Media.Animation.DoubleAnimation(0, TimeSpan.FromSeconds(0.25));
            anim.Completed += (s, _) => Close();
            BeginAnimation(OpacityProperty, anim);
        }

        private void MinimizeButton_MouseDown(object sender, MouseButtonEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void Grid_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            DragMove();
        }
    }
}