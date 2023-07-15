
rule i3e9_07179e89cc010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.07179e89cc010b12"
     cluster="i3e9.07179e89cc010b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['3c792adb8800a4a323f3758c1e42d6a5','6771313e03a989573328f81344830afc','e80a946950379ceaa8f04ef8bb2f03f4']"

   strings:
      $hex_string = { 8c6569ed85acbf7a4cdb7d0d7722f71b6b2ab69c8b3dcdc5f4e27f39d650d815ef8762adbd217daffd74f0ee9efc36e6f7c4d3f0f2a6d8505cf3b6187b6d53ec }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
