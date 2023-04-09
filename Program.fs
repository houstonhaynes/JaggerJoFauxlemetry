namespace JaggerJoFauxlemetry

open System.Threading
open Avalonia
open Avalonia.Controls.ApplicationLifetimes
open Avalonia.FuncUI
open Avalonia.Themes.Fluent

/// This is your application you can ose the initialize method to load styles
/// or handle Life Cycle events of your application
type App() =
    inherit Application()
    
    override this.Initialize() =
        this.Styles.Add (FluentTheme(baseUri = null, Mode = FluentThemeMode.Dark))
        this.Styles.Load "avares://JaggerJoFauxlemetry/Styles.xaml"

    override this.OnFrameworkInitializationCompleted() =
        match this.ApplicationLifetime with
        | :? IClassicDesktopStyleApplicationLifetime as desktopLifetime ->
            desktopLifetime.MainWindow <- Shell.MainWindow()
        | _ -> ()
        
                
           
module Program =
    
    [<EntryPoint>]    
    let main (args: string []) =
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .UseSkia()
            .StartWithClassicDesktopLifetime(args) |> ignore
            
        let task =
            async {
                while true do
                    do Thread.Sleep(1000)
                    printfn "loop"
                    while Counter.volume > 0 do 
                        createMomentForCompany Counter.volume |> ignore
            }
                
        Async.StartImmediate(task)

        0
