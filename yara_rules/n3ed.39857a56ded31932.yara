
rule n3ed_39857a56ded31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a56ded31932"
     cluster="n3ed.39857a56ded31932"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['0476de6f60f9b157dcf070b1b9f7fcd5','194a39cfb228868eda6ea0a83dca434f','d4cdd468a6e16cd9e585dde570aa58d4']"

   strings:
      $hex_string = { 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
