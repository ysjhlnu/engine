package model

import "time"

type UserLoginData struct {
	ID         int       `gorm:"primaryKey;column:id;type:int;not null" json:"id"`
	Name       string    `gorm:"unique;column:name;type:varchar(128);not null" json:"name"`                                                 // 账号
	SystemName string    `gorm:"column:system_name;type:varchar(128);not null;default:智慧电网管理平台" json:"system_name"`                         // 系统名称
	NickName   string    `gorm:"column:nick_name;type:varchar(128);not null" json:"nick_name"`                                              // 姓名
	Phone      string    `gorm:"column:phone;type:varchar(30)" json:"phone"`                                                                // 电话号码
	Email      string    `gorm:"column:email;type:varchar(50)" json:"email"`                                                                // 邮箱
	Pwd        string    `gorm:"column:pwd;type:char(60)" json:"pwd"`                                                                       // 密码
	Token      string    `gorm:"column:token;type:char(32);not null;default:''" json:"token"`                                               // 认证码
	Openid     string    `gorm:"column:openid;type:char(32)" json:"openid"`                                                                 // 统一认证平台id
	Oname      string    `gorm:"column:oname;type:varchar(45)" json:"oname"`                                                                // 统一认证平台昵称
	Status     uint8     `gorm:"column:status;type:tinyint unsigned;default:null;default:0;comment:'状态 0禁用 1启用'" json:"status"`             // 状态 0禁用 1启用
	LoginTime  time.Time `gorm:"column:login_time;type:datetime;default:null;default:0000-01-01 00:00:00;comment:'登陆时间'" json:"login_time"` // 登陆时间
	CreatedAt  time.Time `gorm:"column:created_at;type:datetime;default:0000-01-01 00:00:00" json:"created_at"`                             // 创建时间
	DeptID     []int     `gorm:"-" json:"dept_id"`                                                                                          // 所属部门
	RoleID     []int     `gorm:"-" json:"role_id"`                                                                                          // 所属角色
}
