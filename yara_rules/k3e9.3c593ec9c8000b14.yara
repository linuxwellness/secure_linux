
rule k3e9_3c593ec9c8000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c593ec9c8000b14"
     cluster="k3e9.3c593ec9c8000b14"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy simbot backdoor"
     md5_hashes="['4705ba4f6d06f97cc1ac4b919b2dd5b1','66ab2c0649042fa9e1fc64956418f076','e8e50e6691e2819d5a74e188db0a5e30']"

   strings:
      $hex_string = { 5400720061006e0073006c006100740069006f006e00000000000904b00450414444494e47585850414444494e4750414444494e47585850414444494e475041 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
