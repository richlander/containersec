using System;
using System.Collections.Generic;
using containersec;

public class Analysis
{
    public static VulnerabilitySummary GetVulnerabilitySummary(List<Vulnerability> vulnerabilities)
    {
        var summary = new VulnerabilitySummary();

        foreach (var vuln in vulnerabilities)
        {
            switch (vuln.severity)
            {
                case "Critical": 
                    summary.Critical++;
                    break;
                case "High":
                    summary.High++;
                    break;
                case "Medium":
                    summary.Medium++;
                    break;
                case "Low":
                    summary.Low++;
                    break;
                case "Negligible":
                    summary.Negligible++;
                    break;
                case "Unknown":
                    summary.Unknown++;
                    break;
                default:
                    throw new Exception();
            };
        }

        return summary;
    }

}