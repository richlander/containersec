using System;
using System.Diagnostics;

public static class Docker
{
    public static int PullImage(string image)
    {
        var pull = $"pull {image}";
        var process = Process.Start("docker", pull);
        process.WaitForExit();
        return process.ExitCode;
    }

    public static (int, string) GetTimestampForImage(string image)
    {
        var inspect = "inspect --format={{.Created}}" + $" {image}";
        var start = new ProcessStartInfo("docker");
        start.Arguments = inspect;
        start.RedirectStandardOutput = true;
        var process = Process.Start(start);
        var date = string.Empty;
        using (var stream = process.StandardOutput)
        {
            string output = null;
            while ((output = stream.ReadLine()) != null)
            {
                date = output;
            }
        }

        process.WaitForExit();

        var index = date.IndexOf('.');
        var shortDate = date.Substring(0, index) + "Z";

        return (process.ExitCode, shortDate);
    }
}