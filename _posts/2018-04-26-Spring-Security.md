---
layout: post
title:  "Spring Boot 整合 Spring Security "
date:   2016-05-13 13:25:35 +0200
categories: jekyll update
---

在本例中，主要讲解spring-boot与spring-security的集成，实现方式为：

* 将用户、权限、资源（url）采用数据库存储  
* 自定义过滤器，代替原有的 FilterSecurityInterceptor
* 自定义实现 UserDetailsService、AccessDecisionManager和InvocationSecurityMetadataSourceService，并在配置文件进行相应的配置
 
 ## 用户角色表（基于RBAC权限控制）
 * 用户表
| Name | Academy | score | 
| --- | --- | --- | 
| Harry Potter | Gryffindor| 90 | 
| Hermione Granger | Gryffindor | 100 | 
| Draco Malfoy | Slytherin | 90 |