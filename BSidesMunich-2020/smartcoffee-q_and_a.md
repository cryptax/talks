# Q&A for Hacking Your Smart Coffee Machine

## How did you know this smart coffee machine would be 'hackable'?

I did not. I purchased the machine without any guarantee I would be able to do a challenge out of it. However, I knew the coffee machine supported BLE and had a Android application, which are two areas I have some 'expertise' on. So, I hoped that would help me out.

## How did you figure out the authorization code?

The authorization code would be sent *after* pairing, but before any coffee could be prepared. I parsed all Bluetooth packets between those 2 points, and quickly identified this packet with a strange payload. I tried it, and noticed I was then able to access much more characteristics.


## Why couldn't the authorization code be in pairing?

Everything is "possible", but it was very unlikely to be in pairing. Pairing follows a standard protocol in BLE, and it sets *authentication* and *encryption*. There is no mention of *authorization*.

## Have you tried to do something else with the machine?

Some coffee machine support *recipes*, where you can specify the amount of coffee and water (and milk) you want. Unfortunately, this was not supported on my coffee machine.

I did not try any hardware hack. However I identified the BLE chip used onboard:  BL600-SA-06

## What kept teams back on this challenge?

1. Several teams struggled to find the authorization code because they were looking for it in the SMP packets (pairing protocol).
2. Working with BLE can be painful with unexpected disconnects. This complicates research.
3. Some teams had difficulties understanding the Android app's code.

## Have you contacted the vendor to let them know you added the volume feature?

No, I haven't because (1) it is a minor feature, (2) the feature exists, it's just probably they haven't thought it worth to be configurable by the end-user, (3) the coffee machine exists under several names and brands, and I am a bit lost who I should have contacted.

## Have you found or reported any vulnerability on this coffee machine?

I found it interesting for Ph0wn to focus on a pure hack, i.e something that adds unexpected functionality to the device. Consequently, I did not search at all for any security vulnerability.

## Why haven't they made the smart coffee machine available via Wifi?

Beats me. The fact only one smartphone can be paired at a given time and use the machine is a strong limitation. I don't understand why they haven't added a small embedded website, or something like that. Maybe because BLE was the cheapest solution?


## Bonus

- Code: https://github.com/cryptax/webpresso
- Hackable Magazine article, in French: https://boutique.ed-diamond.com/numeros-deja-parus/1527-hackable-magazine-33.html
- Tech notes: https://fortiguard.com/events/3595/bsides-munich-2020-hacking-your-smart-coffee-machine
