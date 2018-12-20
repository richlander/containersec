using System;
using System.Collections.Generic;
using containersec;

public class DigestInfo
{
    public string digest;
    public string image_type = "docker";
    public string tag;
    public string created_at;

    //public Dictionary<string,List<Vulnerability>> Vulnerabilities = new Dictionary<string, List<Vulnerability>>();
}