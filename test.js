Java.perform(function () {
    var hashMap = Java.use("java.util.HashMap");
    hashMap.put.implementation = function (a, b) {
        console.log("hashMap.put: ", a, b);
        return this.put(a, b);
    }
})
Java.perform(function WebView() {
    let WebView = Java.use("android.webkit.WebView");
    WebView["postUrl"].implementation = function (str, bArr) {
        var string = java.use('java.lang.String').$new(bArr);
        console.log(`WebView.postUrl is called: str=${str}, string=${string}`);
        this["postUrl"](str, bArr);
    };
    WebView["loadUrl"].overload('java.lang.String').implementation = function (str) {
        console.log(`WebView.loadUrl is called: str=${str}`);
        var s = Java.use('java.lang.String').$new(str);
        var t = Java.use('java.lang.String').$new("https");
        if (s.contains(t)) {
            getStackTraceString();
        }
        this["loadUrl"](str);
    };
    WebView["loadUrl"].overload('java.lang.String', 'java.util.Map').implementation = function (str, map) {
        console.log(`WebView.loadUrl 2is called: str=${str}, map=${map}`);
        this["loadUrl"](str, map);
    };
})
com.douban.frodo
com.example.hellomoto
{
  "result": {
    "status": "success",
    "count": 35,
    "applications": [
      {
        "identifier": "com.android.chrome",
        "name": "Chrome",
        "pid": 20953
      },
      {
        "identifier": "com.google.android.gm",
        "name": "Gmail",
        "pid": 0
      },
      {
        "identifier": "com.google.android.googlequicksearchbox",
        "name": "Google",
        "pid": 3700
      },
      {
        "identifier": "com.android.vending",
        "name": "Google Play 商店",
        "pid": 21022
      },
      {
        "identifier": "com.example.hellomoto",
        "name": "HelloMoto",
        "pid": 0
      },
      {
        "identifier": "bin.mt.plus",
        "name": "MT管理器",
        "pid": 0
      },
      {
        "identifier": "com.google.android.apps.tips",
        "name": "Pixel 使用提示",
        "pid": 0
      },
      {
        "identifier": "com.reqable.android",
        "name": "Reqable",
        "pid": 0
      },
      {
        "identifier": "com.google.android.youtube",
        "name": "YouTube",
        "pid": 0
      },
      {
        "identifier": "com.google.android.apps.youtube.music",
        "name": "YouTube Music",
        "pid": 0
      },
      {
        "identifier": "com.marriott.mrt",
        "name": "万豪旅享家",
        "pid": 0
      },
      {
        "identifier": "com.google.android.apps.safetyhub",
        "name": "个人安全",
        "pid": 0
      },
      {
        "identifier": "com.google.android.apps.docs",
        "name": "云端硬盘",
        "pid": 0
      },
      {
        "identifier": "com.google.android.apps.messaging",
        "name": "信息",
        "pid": 3723
      },
      {
        "identifier": "com.google.android.apps.maps",
        "name": "地图",
        "pid": 0
      },
      {
        "identifier": "com.xiaojia.xgj",
        "name": "小工具",
        "pid": 0
      },
      {
        "identifier": "com.google.android.apps.recorder",
        "name": "录音机",
        "pid": 0
      },
      {
        "identifier": "com.smile.gifmaker",
        "name": "快手",
        "pid": 32303
      },
      {
        "identifier": "com.google.android.apps.nbu.files",
        "name": "文件极客",
        "pid": 0
      },
      {
        "identifier": "com.google.android.calendar",
        "name": "日历",
        "pid": 0
      },
      {
        "identifier": "com.google.android.deskclock",
        "name": "时钟",
        "pid": 0
      },
      {
        "identifier": "com.byd.sea",
        "name": "比亚迪海洋",
        "pid": 0
      },
      {
        "identifier": "com.lucky.luckyclient",
        "name": "瑞幸咖啡",
        "pid": 0
      },
      {
        "identifier": "com.google.android.dialer",
        "name": "电话",
        "pid": 0
      },
      {
        "identifier": "com.google.android.apps.photos",
        "name": "相册",
        "pid": 0
      },
      {
        "identifier": "com.google.android.GoogleCamera",
        "name": "相机",
        "pid": 0
      },
      {
        "identifier": "com.google.android.calculator",
        "name": "计算器",
        "pid": 0
      },
      {
        "identifier": "com.android.settings",
        "name": "设置",
        "pid": 19041
      },
      {
        "identifier": "com.example.tee4",
        "name": "证书查看器",
        "pid": 0
      },
      {
        "identifier": "com.douban.frodo",
        "name": "豆瓣",
        "pid": 19840
      },
      {
        "identifier": "com.wandoujia.phoenix2",
        "name": "豌豆荚",
        "pid": 0
      },
      {
        "identifier": "com.google.android.contacts",
        "name": "通讯录",
        "pid": 0
      },
      {
        "identifier": "com.coolapk.market",
        "name": "酷安",
        "pid": 0
      },
      {
        "identifier": "mobi.w3studio.apps.android.shsmy.phone",
        "name": "随申办市民云",
        "pid": 0
      },
      {
        "identifier": "com.ziipin.homeinn",
        "name": "首旅如家",
        "pid": 0
      }
    ]
  }
}