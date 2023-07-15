
rule k3e9_2b95f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b95f3a9c8000b32"
     cluster="k3e9.2b95f3a9c8000b32"
     cluster_size="30"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor tofsee injector"
     md5_hashes="['0c06fd394ecb4d5a984bcb42e40200f7','398cce3aae4cab4373008458bc42ea7e','b32c80b0499934781fb2d6692699bdd7']"

   strings:
      $hex_string = { 8847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de067 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
