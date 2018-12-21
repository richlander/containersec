using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace containersec
{
    public class ImageInfo
    {
        [JsonProperty("digest")]
        public string Digest;
        [JsonProperty("imageId")]
        public string ImageId;

        [JsonProperty("image_type")]
        public string Type = "docker";
        [JsonProperty("tag")]
        public string Tag;
        [JsonProperty("created_at")]
        public string TimeStamp;

        //public Dictionary<string,List<Vulnerability>> Vulnerabilities = new Dictionary<string, List<Vulnerability>>();
    }
}