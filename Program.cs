using System;
using System.IO;
using System.Threading.Tasks;
using static System.Console;

namespace containersec
{
    class Program
    {
        static async Task Main(string[] args)
        {

            var status = await Anchore.CheckStatus();

            if (!status)
            {
                WriteLine($"Anchore Engine is not available at {Anchore.BaseUrl}");
                return;
            }

            void PrintMenu()
            {
                WriteLine("commands:");
                WriteLine("  help -- prints help");
                WriteLine("  list -- lists images");
                WriteLine("  add [file] -- add images in file");
                WriteLine("  vuln [image] [high | low | all] -- summarizes vulnerabilities for image");
                WriteLine("  q -- quits program");
            }

            await VulnerabilityAnalysis.DiffVulnerabilities();

            string input = "help";
            while (true)
            {
                if (input == "q")
                {
                    return;
                }
                else if (input == "help")
                {
                    PrintMenu();
                }
                else if (input.StartsWith("addtag"))
                {
                    var arguments = input.Split(' ');
                    await ImageLoad.Image(arguments[1]);

                }
                else if (input.StartsWith("add"))
                {

                    await ImageLoad.ImagesFromFile(new FileInfo(@"c:\git\containersec\images.txt"));

                }
                else if (input.StartsWith("process"))
                {
                    var logLocation = Path.Combine(Directory.GetCurrentDirectory(),"logs");
                    await VulnerabilityAnalysis.ProcessImages(new DirectoryInfo(logLocation));
                }
                else if (input == "list")
                {
                    await foreach (var image in Anchore.GetImages())
                    {
                        var analysis = (image.Analysis == "analyzed") ? string.Empty : $"[{image.Analysis}] ";
                        WriteLine($"{analysis}{image.Tag}");
                    }
                }
                else if (input.StartsWith("vuln"))
                {
                    var arguments = input.Split(' ');

                    if (arguments.Length <2)
                    {
                        WriteLine("Missing argument -- specify image");
                    }
                    else
                    {
                        var vulnerabilities = await Anchore.GetVulnerabilitiesForTag(arguments[1]);
                        var summary = VulnerabilityAnalysis.GetSummary(vulnerabilities);
                        
                        if (arguments.Length == 3)
                        {
                            var severityLevel = arguments[2];
                            var (valid, count) = VulnerabilityAnalysis.GetCountForSeverityLevel(summary, severityLevel);
                            
                            if (valid)
                            {
                                WriteLine($"{severityLevel}: {count}");
                            }
                            else
                            {
                                WriteLine($"{severityLevel} not a valid severity level");
                            }
                        }
                        else
                        {
                            WriteLine(summary);
                        }
                    }
                }
                else
                {
                    WriteLine("Unknown command");
                }
                WriteLine();
                
                input = ReadLine();
            }
        }
    }
}
