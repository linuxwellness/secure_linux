
rule i3ed_051756abcc668932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.051756abcc668932"
     cluster="i3ed.051756abcc668932"
     cluster_size="72"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue generickdz debris"
     md5_hashes="['0921a4ab2fa83045153357df95ad072d','09a6558ca5b3346f86e43d5928f54329','4a61ec1d6aaa3a874b4d0e47f65e492c']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a15030001083ee04ebea50ff151020001083255030001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
