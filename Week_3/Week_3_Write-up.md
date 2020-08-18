# Week_3_Write-Up

##### 서론

오랜만에 하는 웹해킹이라 감이 많이 죽었을까봐 걱정하는 마음이 컸지만, 15번을 10분만에 풀어내는 것을 보고서는 안도감에 가슴을 쓸어내렸다. 최근에 Dreamhack에서 열심히 강좌를 공부했었는데, 거기서 봤던 테크닉들이 상당히 유용했다. 의외의 것들도 많이 알게 되었는데, Buffer Overflow가 Assembly단이 아닌, C언어와 같이 고수준에서도 충분히 분석할 수 있다는 점에서 상당히 놀랐다. 어셈블리의 Stack Frame을 공부하면서 배운 것도 많고, 이번에 어셈블리 스터디를 들어 x86 프로세서와 NASM 어셈블리를 어느 정도 완성하고 나면 본격적으로 포너블을 다뤄보고 싶다는 마음이 들었다.



#### 1. Webhacking.kr No.24

##### 1) 문제 분석

![1-1](Img/1-1.png)

갑자기 뜬끔없이 내 IP주소를 보여주니 당황스럽기 그지없다.

밑에 view-source를 확인하여 보자.

```php+HTML
<?php
  include "../../config.php";
  if($_GET['view_source']) view_source();
?><html>
<head>
<title>Challenge 24</title>
</head>
<body>
<p>
<?php
  extract($_SERVER);
  extract($_COOKIE);
  $ip = $REMOTE_ADDR;
  $agent = $HTTP_USER_AGENT;
  if($REMOTE_ADDR){
    $ip = htmlspecialchars($REMOTE_ADDR);
    $ip = str_replace("..",".",$ip);
    $ip = str_replace("12","",$ip);
    $ip = str_replace("7.","",$ip);
    $ip = str_replace("0.","",$ip);
  }
  if($HTTP_USER_AGENT){
    $agent=htmlspecialchars($HTTP_USER_AGENT);
  }
  echo "<table border=1><tr><td>client ip</td><td>{$ip}</td></tr><tr><td>agent</td><td>{$agent}</td></tr></table>";
  if($ip=="127.0.0.1"){
    solve(24);
    exit();
  }
  else{
    echo "<hr><center>Wrong IP!</center>";
  }
?><hr>
<a href=?view_source=1>view-source</a>
</body>
</html>
```

코드를 분석하여보면.

1. Server와 Cookie를 Extract한다.
2. $REMOTE_ADDR를 $ip로 가져온다.
3. $ip를 str_replace를 이용해 필터링한다.
4. $ip가 127.0.0.1이면 Solve.

여기서 처음에 든 생각은, 'REMOTE_ADDR이 127.0.0.1이면 Response가 루프백으로 전송될텐데?'였다. 프록시를 통해 패킷을 변조해 보내 solve(24)를 실행시킨다 쳐도, 여기서는 확인할 길이 없을 것이다. 그러면 어디서 바꿔치기해야하는 지 고민하던 찰나에, $REMOTE_ADDR을 $ip로 대입시키는 모습에서 "왜 굳이 $ip로 변수를 옮기지?"라는 생각을 하였고, 그 해답은 위의 extract($_COOKIE);에 있었다. 최근 드림핵에서 PHP의 보안 취약점으로 쿠키의 이름이 Request 변수를 덮어씌울 수 있다는 것을 공부하였다. 그렇다면.......

##### 2) 풀이 과정

쿠키에 REMOTE_ADDR를 생성하고, 그 안에 임의의 문자열을 삽입한 후, 새로고침 해보니.......

![1-2](Img/1-2.png)

예상대로이다. 쿠키를 추출하면서 $REMOTE_ADDR이 덮어씌워졌고, $ip에는 쿠키에 있던 $REMOTE_ADDR이 들어간 것이다. 이제는 다음으로 str_replace를 해결하면 되는데, 이것또한 어려운 것이 아니었다. 입력하고자 하는 값은 127.0.0.1이고, 12와 7., 0., ..이 바뀐다. 이러한 점을 생각하여 String을 구상하여보면 쉽다.

![AA](Img/1-3.png)

그렇게 완성된 문자열은  "112277...00...00...1". 이것을 쿠키값에 넣고 결과를 확인해보자.

##### 3) 결과 확인

![1-4](Img/1-4.png)

(거위는 무시하자)

제대로 작동한 것이 보인다.

#### 2. Webhacking.kr No.18

##### 1) 문제 분석

![2-1](Img/2-1.png)

 SQL Injection이라고 대놓고 박혀있다.

그 말은, SQL Query문과 Filtering에서 막히지 않은 벽이 하나 있다는 말일 것이다. 소스코드를 통해서 확인해보도록 하자.

```php+HTML
<?php
  include "../../config.php";
  if($_GET['view_source']) view_source();
?><html>
<head>
<title>Challenge 18</title>
<style type="text/css">
body { background:black; color:white; font-size:10pt; }
input { background:silver; }
a { color:lightgreen; }
</style>
</head>
<body>
<br><br>
<center><h1>SQL INJECTION</h1>
<form method=get action=index.php>
<table border=0 align=center cellpadding=10 cellspacing=0>
<tr><td><input type=text name=no></td><td><input type=submit></td></tr>
</table>
</form>
<a style=background:gray;color:black;width:100;font-size:9pt;><b>RESULT</b><br>
<?php
if($_GET['no']){
  $db = dbconnect();
  if(preg_match("/ |\/|\(|\)|\||&|select|from|0x/i",$_GET['no'])) exit("no hack");
  $result = mysqli_fetch_array(mysqli_query($db,"select id from chall18 where id='guest' and no=$_GET[no]")); // admin's no = 2

  if($result['id']=="guest") echo "hi guest";
  if($result['id']=="admin"){
    solve(18);
    echo "hi admin!";
  }
}
?>
</a>
<br><br><a href=?view_source=1>view-source</a>
</center>
</body>
</html>
```

여기서 SQL Query는 "select id from chall18 where id='guest' and no=$_GET[no]"인데, 여기서 다음 줄에 guest인 것이 확인되면 guest 아이디로 인식되므로, where 문 전체를 무력화시킬 필요가 있을 것이다. 

