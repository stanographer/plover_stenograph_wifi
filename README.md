# Plover Stenograph Wi-Fi

This Plover plugin allows you to use Diamanté or Luminex machines with Wi-Fi capability.
Based on [work](https://github.com/morinted/plover_stenograph_usb) by Ted Morin & Keith McReady.

### To install:

1. Download the repo.
2. Navigate to it in your terminal.
3. Make sure you have Python and Pip installed and do `pip3 install -e .`

### To use:

1. Turn on your Diamanté or Luminex and make sure you have both the hardware capability forWi-Fi and have it enabled in your settings.
2. Connect to the same Wi-Fi network as your computer running Plover.
3. Begin Plover.
4. If not already selected, select "Stenograph Wi-Fi" from the options.

That's it! If it disconnects, it should already reconnect when you're in range.
But if it's not connecting, try hitting the reconnect button in Plover.

## Tested Machines
Stenograph Luminex ([Build #17513, 1 August 2018](http://www.stenograph.com/writer-downloads))

### Improvements:

1. For now it works pretty well. There are a couple of bugs like when you lose connection, sometimes it freezes.
2. Get it on pip.