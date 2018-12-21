using System;
using System.IO;
using System.Threading.Tasks;
using containersec;

public class Load
{
    public static async Task FromImageFile(FileInfo file)
    {
        var stream = file.OpenText();
        
        await foreach(var line in GetLinesForStreamReader(streamReader))
        {
            var image = new ImageInfo();
            image.Tag = line;
            await Anchore.RegisterImage(image);
        }
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