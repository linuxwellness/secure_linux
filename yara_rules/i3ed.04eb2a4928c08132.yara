
rule i3ed_04eb2a4928c08132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.04eb2a4928c08132"
     cluster="i3ed.04eb2a4928c08132"
     cluster_size="46"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris zusy gamarue"
     md5_hashes="['0366e670d56d649fda487b4a7b0a16c6','1b5c84f2e3a700218674516934e3d237','a7d6e33b91a2c5b3839eb79d75ee680c']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a14032001083ee04ebea50ff151820001083254032001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
