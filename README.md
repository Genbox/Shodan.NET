## Introduction

The Shodan.NET class library provides a WebAPI class to Search() and GetHost()-information. It currently relies .NET 4.0 and help is welcome for making it compatible with earlier .NET releases.

## Usage

Before you can use the API, you need to have an API key.

[Get your API key here](http://www.shodanhq.com/api_doc)

Setup the SHODAN WebAPI:
```csharp
	using Shodan;
	
	WebAPI api = new WebAPI("YOUR KEY");
```

Print a list of cisco-ios devices:
```csharp
	SearchResult results = api.Search("cisco-ios");

    foreach (Host h in results.Hosts)
    {
        Console.WriteLine(h.IP.ToString());
    }
```

Get all the information SHODAN has on the IP 217.140.75.46:
```csharp
	Host host = api.GetHost("217.140.75.46");
	Console.WriteLine(host.IP.ToString());
```

Search for exploits on ExploitDB and modules on MSF:
```csharp
	List<Exploit> exploits = api.SearchExploits("Microsoft Windows XP");

	foreach (Exploit exploit in exploits)
	{
		Console.WriteLine(exploit.Description);
	}
	
	List<MSFModule> modules = api.SearchMSFModules("Oracle");

	foreach (MSFModule msfModule in modules)
	{
		Console.WriteLine(msfModule.Name);
	}
```

Download exploit from ExploitDB and modules from MSF:
```csharp
	DataResponse exploit = api.DownloadExploit(17133);
	Console.WriteLine(exploit.Filename);

	//Note that we also write the file to disk
	DataResponse module = api.DownloadMSFModule("exploit/windows/browser/ms06_055_vml_method");
	module.WriteToFile("C:\\" + module.Filename);
	Console.WriteLine(module.Filename);
```