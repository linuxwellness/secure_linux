
rule k3e9_51a931060d6b6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51a931060d6b6b32"
     cluster="k3e9.51a931060d6b6b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['a9361ece0aaca7b72d9e9473b03320df','cc596ca77f57d27268841780e9236f49','d86fbb99cb0621dc862bb7ce4f63a49a']"

   strings:
      $hex_string = { 33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c40001000061c9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
