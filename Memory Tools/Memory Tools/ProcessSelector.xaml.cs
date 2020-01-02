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
using System.Drawing;
using System.IO;
using System.Drawing.Imaging;
using System.Diagnostics;
using System.ComponentModel;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;

namespace Memory_Tools
{
    /// <summary>
    /// Interaction logic for ProcessSelector.xaml
    /// </summary>

    public class ImageConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is Bitmap)
            {
                var stream = new MemoryStream();
                ((Bitmap)value).Save(stream, ImageFormat.Png);

                BitmapImage bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.StreamSource = stream;
                bitmap.EndInit();

                return bitmap;
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public partial class ProcessSelector : Window
    {
        public class SampleModel
        {
            public IEnumerable<ViewData> Items
            {
                get
                {
                    System.Windows.Forms.Cursor.Current = System.Windows.Forms.Cursors.WaitCursor;
                    foreach (Process process in Process.GetProcesses("."))
                    {
                        Icon ico;
                        try
                        {
                            ico = System.Drawing.Icon.ExtractAssociatedIcon(process.MainModule.FileName);
                        }
                        catch (FileNotFoundException) { continue; }
                        catch (Win32Exception) { continue; }
                        catch (InvalidOperationException) { continue; }

                        if (!process.HasExited)
                        {
                            if (string.IsNullOrWhiteSpace(process.MainWindowTitle))
                            {
                                Bitmap bmp = System.Drawing.Icon.ExtractAssociatedIcon(process.MainModule.FileName).ToBitmap(); // Crashes if file can't be found
                                yield return new ViewData(bmp, " " + process.ProcessName, process);
                            }
                            else
                            {
                                Bitmap bmp = System.Drawing.Icon.ExtractAssociatedIcon(process.MainModule.FileName).ToBitmap(); // Crashes if file can't be found
                                yield return new ViewData(bmp, " " + process.MainWindowTitle, process);
                            }
                        }
                    }
                    System.Windows.Forms.Cursor.Current = System.Windows.Forms.Cursors.Default;
                }
            }
        }

        public class ViewData
        {
            public ViewData(Bitmap icon, string name, Process process)
            {
                _icon = icon;
                _name = name;
                Process = process;
            }

            private readonly Bitmap _icon;
            public Bitmap Icon
            {
                get
                {
                    return _icon;
                }
            }

            private readonly string _name;
            public string Name
            {
                get
                {
                    return _name;
                }
            }

            public Process Process;
        }

        public ProcessSelector()
        {
            InitializeComponent();
            DataContext = new SampleModel();
        }

        private void OK_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem == null)
            {
                Error err = new Error("No processes have been selected.");
                err.Show();
                return;
            }
            else if (ProcessList.SelectedItems.Count > 1)
            {
                Error err = new Error("Only 1 process can be selected at a time.");
                err.Show();
                return;
            }

            MainWindow.SelectedProcess = ((ViewData)ProcessList.SelectedItem).Process;
            MainWindow.CurrentInstance.LoadModules();
            MainWindow.has_selected_process = true;
            MainWindow.Proc_check.Abort();

            MainWindow.Proc_check = new System.Threading.Thread(MainWindow.CheckProcess);
            MainWindow.Proc_check.Start();
            MainWindow.CurrentInstance.ReloadThreads(MainWindow.SelectedProcess);
            Window_Closing(null, new CancelEventArgs());
        }

        private void Reload_Click(object sender, RoutedEventArgs e)
        {
            Title = "Process Selector - Loading Processes";
            DataContext = new SampleModel();
            Title = "Process Selector";
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            Window_Closing(null, new CancelEventArgs());
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            Closing -= Window_Closing;
            e.Cancel = true;
            var anim = new DoubleAnimation(0, TimeSpan.FromSeconds(0.25));
            anim.Completed += (s, _) => Close();
            BeginAnimation(OpacityProperty, anim);
        }

        private void Grid_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            DragMove();
        }

        public void CloseWindow(object sender, RoutedEventArgs e)
        {
            Window_Closing(null, new CancelEventArgs());
        }

        private void CloseButton_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Window_Closing(null, new CancelEventArgs());
        }

        private void MinimizeButton_MouseDown(object sender, MouseButtonEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }
    }
}
