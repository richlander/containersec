using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using containersec;
using static System.Console;

public static class Image
{
    public static async Task LoadFromFile(FileInfo file)
    {
        var streamReader = file.OpenText();
        string line = string.Empty;

        while ((line = await streamReader.ReadLineAsync()) != null)
        {
            var image = new ImageInfo();
            image.Tag = line;
            Docker.PullImage(image.Tag);
            var (code, timeStamp) = Docker.GetTimestampForImage(image.Tag);
            image.TimeStamp = timeStamp;
            var result = await Anchore.RegisterImage(image);
            WriteLine($"Added: {image.Tag}; Analyzed: {result}");
        }
    }

    public static async Task Load(string tag)
    {
        var image = new ImageInfo();
        image.Tag = tag;
        Docker.PullImage(image.Tag);
        var (code, timeStamp) = Docker.GetTimestampForImage(image.Tag);
        image.TimeStamp = timeStamp;
        var result = await Anchore.RegisterImage(image);
        WriteLine($"Added: {image.Tag}; Analyzed: {result}");
    }
}
