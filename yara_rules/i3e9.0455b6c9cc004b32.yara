
rule i3e9_0455b6c9cc004b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.0455b6c9cc004b32"
     cluster="i3e9.0455b6c9cc004b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['0428cbea22ab6c41409f22145fb1b140','10a748837b096597e2f622f46942bfdc','94af5efa0d7ccf4e65ea94777a446ee8']"

   strings:
      $hex_string = { 8b85107eb6e3a9cafcf3c5cab14a657e263cbdb3b258af554ad558f246abe444ad540ae11b6d4f95eac7e72f5c28566747e7aaa54238393cfef4f0e8a127b28e }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
