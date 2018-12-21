using System;
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
                WriteLine("  vuln [image] [high | low | all] -- summarizes vulnerabilities for image");
                WriteLine("  q -- quits program");
            }

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
                else if (input.StartsWith("add"))
                {
                    
                }
                else if (input == "list")
                {
                    await foreach (var image in Anchore.GetImages())
                    {
                        WriteLine($"{image.Tag}");
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
                        var vulnerabilities = await Anchore.GetVulnerabilitiesForImage(arguments[1]);
                        var summary = Analysis.GetVulnerabilitySummary(vulnerabilities);
                        
                        if (arguments.Length == 3)
                        {
                            var severityLevel = arguments[2];
                            var (valid, count) = GetVulnerabilityCountForSeverityLevel(summary, severityLevel);
                            
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

            (bool, int) GetVulnerabilityCountForSeverityLevel(VulnerabilitySummary summary ,string severity)
            {
                var count = 0;
                switch (severity.ToLowerInvariant())
                {
                    case "critical":
                        count = summary.Critical;
                        break;
                    case "high":
                        count = summary.High;
                        break;
                    case "medium":
                        count = summary.Medium;
                        break;
                    case "low":
                        count = summary.Low;
                        break;
                    case "negligible":
                        count = summary.Negligible;
                        break;
                    case "Unknown":
                        count = summary.Unknown;
                        break;
                    default:
                        return (false, 0);
                };

                return (true, count);
            }       
        }
    }
}
