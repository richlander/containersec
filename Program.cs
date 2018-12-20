using System;
using System.Threading.Tasks;
using static System.Console;

namespace containersec
{
    class Program
    {
        static async Task Main(string[] args)
        {

            if (args == null || args.Length < 2)
            {
                WriteLine("Input arguments are incorrect.");
                return;
            }

            // Supported arguments:
            // image-add [image]
            // image-summary [image]
            // digest-summary [digest]

            if (args[0] == "image-add")
            {
                var result = await Anchore.RegisterImage(args[1]);
            }

            var status = await Anchore.CheckStatus();

            if (!status)
            {
                WriteLine($"Anchore Engine is not available at {Anchore.BaseUrl}");
            }

            
            
        }
    }
}
