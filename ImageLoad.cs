using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using containersec;
using static System.Console;

public static class ImageLoad
{
    public static async Task ImagesFromFile(FileInfo file)
    {
        var streamReader = file.OpenText();
        
        await foreach(var line in GetLinesForStreamReader(streamReader))
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

    public static async Task Image(string tag)
    {
        var image = new ImageInfo();
        image.Tag = tag;
        Docker.PullImage(image.Tag);
        var (code, timeStamp) = Docker.GetTimestampForImage(image.Tag);
        image.TimeStamp = timeStamp;
        var result = await Anchore.RegisterImage(image);
        WriteLine($"Added: {image.Tag}; Analyzed: {result}");
    }


    private static async IAsyncEnumerable<string> GetLinesForStreamReader(StreamReader streamReader)
    {
        string line = string.Empty;
        while ((line = await streamReader.ReadLineAsync()) != null)
        {
            yield return line;
        }
    }
}