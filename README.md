# log-slapper 🪵🪓👹
<p align="center">
<img width="600" align="center" alt="image"  src="https://github.com/user-attachments/assets/ef823bcb-14e6-40d2-a880-ea3572cdda46">
</p>
<br>

<div align="center">
<b>Every company undoubtedly trusts its SIEM, right? Think twice. </b><br>
<b>We can inject fake logs, distract blueteams and hide our attacks thanks to the vulnerable SIEM solutions.</b>
</div>

## description
log-slapper is an offensive security tool designed to be used by red-teamers during the post-exploitation phase. It exploits vulnerable (any Splunk, basically) SIEM solutions and configurations that allow the injection of arbitrary logs into the target system.

log-slapper can:
- mimic attacks on behalf of any other computer on the network
- run in interactive mode: Target Shell Playzone 
- send logs from future and past (time travelling!)
- perform HEC based attacks
- perform built-in attacks like login success/fail login, new process creation events spam in windows
- perform pre-determined attack scenarios using .yaml

## installation

To install log-slapper, you can directly compile the project using the `go build .` command. If you encounter any errors, follow the steps below to ensure all dependencies are installed:

```bash
# clone the Repository:
git clone https://github.com/oz9un/logslapper.git
cd logslapper

# install Dependencies:
sudo apt install libnetfilter-queue-dev
sudo apt install libpcap-dev

# build the project:
go build .
```


## usage


After the first installation, log-slapper needs to create a log.settings file, as it won't be created automatically. This file requires the following information:
- Indexer/HF's IP Address: This is where the logs will be injected.
- HEC Token: Optional, in case you have a HEC token of the target instance.

<img width="600" alt="resim" src="https://github.com/user-attachments/assets/61a41924-d401-4b47-9baf-3d56293db65b">
<br>
<br>
You can manually create and configure the log.settings file with the necessary details. However, if you have root access, you can start log-slapper with `sudo`, and it will automatically find the target Splunk instance's IP address:

```sudo ./logslapper```

<img width="600" alt="resim" src="https://github.com/user-attachments/assets/50f57212-ad01-4fd7-8982-62868e8134a6">
<br>
<br>
After that, you can select the attack type you want from the interactive menu.
<br>
<br>
Besides the interactive menu, you can also select various attack types from the help menu and ran them directly:
<br>
<br>
<img width="600" alt="resim" src="https://github.com/user-attachments/assets/be2cf827-ed47-4e05-9981-ca237c9c4354">
<br>

## create your own attack scenarios to execute

log-slapper allows you to create custom attack scenarios, which can be collected in a single log file (using YAML format) and then provided as input to the tool. With this way, you can basically create any attack scenario in your mind and inject them into the target Splunk instance.

### creating and executing a attack scenario

You can define your attack scenarios in a YAML file, where you can specify the logs, events, and sequences you want to simulate. Once your scenario is ready, save it as attack_template.yaml (or any name you prefer).

To execute log-slapper with your pre-determined attack scenario, use the following command:
```
./log-slapper attack -f attack_template.yaml
```

For the example attack_templates, have a look at the "example-attack-templates" folder.

### using the event genie

There is also a custom chatgpt called "windows event genie", it's just created for to help you along creating windows attack scenarios. You can describe the attack you want to inject and it will create a .yaml for you:

<img width="460" alt="resim" src="https://github.com/user-attachments/assets/46d36531-3395-4b59-80e5-a8b756637816">

[Go to the Event Genie](https://chatgpt.com/g/g-UpEG7btn2-windows-event-log-genie)

## about the research & tool
This tool has been showcased at several security conferences, including:
- BsidesSATX
- BsidesTirana
- Hacktivity
- BsidesPrague

The latest and most powerful version of log-slapper, along with the comprehensive research behind it, is being presented at DEFCON 32 Red Team Village by Özgün Kültekin. This version includes enhanced features and capabilities, making it a must-have tool for any red team operation.
<br>

<p align="center">
<img width="400" align="center" alt="image"  src="https://github.com/user-attachments/assets/655344d4-fea9-4cac-abbb-1fddabfe9771">
</p>
<br>

Now, DEFCON32 slides are publicly available! : 
[The SIEMless Hack: Rewriting Reality with Log Injection](https://github.com/oz9un/log-slapper/blob/main/DEF%20CON%2032%20-%20Red%20Team%20Village%20-%20Ozgun%20Kultekin%20-%20The%20SIEMless%20Hack%20Rewriting%20Reality%20with%20Log%20Injection.pdf)


## changelog: diff between v2 and v1
As with the premiere in Red Team Village @DEFCON32, log-slapper now includes the following functionalities:
- **No Root Access Required**: log-slapper no longer requires root access to inject logs, making it more versatile and easier to use in various environments.
- **Direct TCP Communication**: Logs can be injected to target indexer/hf using direct TCP communication. You don't even have to have Splunk installed on the compromised machine.
- **Custom Attack Scenarios**: Attackers can create their own attack scenarios and provide them as input to log-slapper. The tool can follow these pre-determined attack scenarios, allowing for more precise and controlled testing of SIEM solutions.

