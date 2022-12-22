# 智能家居管理系统（后端服务）

浙江大学 2022 秋冬学期《B/S体系软件设计》期末 Project

[前端项目仓库 yuaanlin/zju-bs-project-frontend](https://github.com/yuaanlin/zju-bs-project-frontend/)

![Design](https://github.com/yuaanlin/zju-bs-project-frontend/raw/main/public/og.png)

## 作者

计算机科学与技术学院 3190106167 林沅霖

## 实验要求

任选 Web 开发技术实现一个用于智能家居设备管理的系统， 需要实现的基本功能如下：

1. 实现用户注册、登录功能，用户注册时需要填写必要的信息并验证，如用户名、密码要求在
   6 字节以上，手机号的格式验证，并保证用户名和手机号在系统中唯一。
2. 用户登录后可以创建场所，然后在场所里创建智能设备（中间可以加一级，就是场所里先创建房间，然后在房间里创建智能设备）
3. 设备类型至少支持以下几种
    1. 灯（支持开关和亮度调节）
    2. 开关
    3. 传感器（温湿度等信息查看）
    4. 门锁（开关门状态上报）
4. 提供列表信息查看设备信息、设备状态和上报信息
5. 提供可视化界面展示以上信息，可以在房间户型图（上传图片）上摆放设备，或者提供画图功能画出场所图
6. 可以在手机上查看，手机应用可以是网页，也可以是app 为了提交作业方便，项目使用的数据库，建议使用
   mysql 或 hsqldb，提交作业时同时附带建表脚本文件。

## 线上环境

这个项目使用 [Zeabur](https://zeabur.com/home/) 进行一站式、全自动的项目部署，且自带 CI/CD 和 SSL 证书。

你可以在 [https://zju-bs-project.zeabur.app/](https://zju-bs-project.zeabur.app/) 访问本项目的线上环境。

![zeabur](https://i.imgur.com/GcZcux4.png)
