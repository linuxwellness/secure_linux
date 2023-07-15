
rule o26bb_612fa160d3d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.612fa160d3d30912"
     cluster="o26bb.612fa160d3d30912"
     cluster_size="59"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious aeahd"
     md5_hashes="['6210c5b715742413b1c10896e2c91a64e462ea6e','9d5eb1041c4647fbc47e420d986977f5aa0623f8','e29e760a01369ef433a0fa10629498b21647ef90']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.612fa160d3d30912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
