using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using System.Threading.Tasks;

namespace AvaloniaDemo;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow();
            
            // Автоматическое завершение через 1.5 сек для автономного демо-профилирования
            Task.Delay(1500).ContinueWith(_ => 
                Avalonia.Threading.Dispatcher.UIThread.Post(() => desktop.Shutdown()));
        }

        base.OnFrameworkInitializationCompleted();
    }
}