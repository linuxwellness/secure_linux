
rule j3e7_7194d6c3c8000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194d6c3c8000110"
     cluster="j3e7.7194d6c3c8000110"
     cluster_size="1633"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['0007969a075026abce870fcffe4d11b9','00107fc2e596a49afafd20eaa6752483','01e1a855d1e77b698b3e29ba4a3d0bb6']"

   strings:
      $hex_string = { 086d436f6e7465787400136d496e697469616c4170706c69636174696f6e000e6d4c6f63616c50726f766964657200096d5061636b61676573000c6d50726f76 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
