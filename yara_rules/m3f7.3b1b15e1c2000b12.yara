
rule m3f7_3b1b15e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.3b1b15e1c2000b12"
     cluster="m3f7.3b1b15e1c2000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker html"
     md5_hashes="['7a26f3b6829efebdc0c2506393c6364a','9b77ceeb69d16b2a9a32e26d28ed8338','e6ba9a831190e9b1a89241535bd32c64']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e744279496428274c6162656c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
