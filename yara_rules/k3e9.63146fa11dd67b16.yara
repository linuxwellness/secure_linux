
rule k3e9_63146fa11dd67b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fa11dd67b16"
     cluster="k3e9.63146fa11dd67b16"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['869db38a26d7392ce6309aa19f095f71','9334d3d71c7c044dbc738c15169976c2','de3cb6e65d523b9e6ffc3b334a43812b']"

   strings:
      $hex_string = { 0077007300280054004d00290020004f007000650072006100740069006e0067002000530079007300740065006d0000003e000d000100500072006f00640075 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
