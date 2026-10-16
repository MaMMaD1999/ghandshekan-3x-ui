package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/session"
	"strconv"
)

func (a *InboundController) pronetCapabilities(c *gin.Context) {
	jsonObj(c, gin.H{"product": "pronet-3x-ui", "accountingVersion": 1, "perUserInboundTraffic": true, "inboundCoefficient": true, "quotaTraffic": "billed", "rawTraffic": true, "coreReady": service.ProNetCoreReady()}, nil)
}
func (a *InboundController) setTrafficCoefficient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"success": false})
		return
	}
	var f struct {
		Rate     *float64 `json:"trafficCoefficient" form:"trafficCoefficient" binding:"required"`
		Expected *float64 `json:"expectedCoefficient" form:"expectedCoefficient"`
	}
	if err = c.ShouldBind(&f); err != nil {
		c.JSON(400, gin.H{"success": false, "msg": err.Error()})
		return
	}
	err = a.inboundService.SetTrafficCoefficient(id, session.GetLoginUser(c).Id, *f.Rate, f.Expected)
	if err != nil {
		c.JSON(409, gin.H{"success": false, "msg": err.Error()})
		return
	}
	jsonObj(c, gin.H{"trafficCoefficient": *f.Rate}, nil)
	a.broadcastInboundsUpdate(session.GetLoginUser(c).Id)
}
