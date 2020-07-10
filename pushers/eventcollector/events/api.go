package events

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var db = make(map[string]string)

func setupRouter() *gin.Engine {
	// Disable Console Color
	// gin.DisableConsoleColor()
	r := gin.Default()


	authorized := r.Group("/", gin.BasicAuth(gin.Accounts{
		"admin": "honeynet_admin",
	}))

	//CORS - specific parameters
/*	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://honeynet.ubiwhere.com"},
		AllowMethods:     []string{"PUT", "PATCH"},
		AllowHeaders:     []string{"Origin"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://github.com"
		},
		MaxAge: 12 * time.Hour,
	}))*/

	//CORS -> allow all origins
	r.Use(cors.Default())

	//setup swagger
	// @title Swagger Example API
	// @version 1.0
	// @description This is the Honeynet server.
	// @termsOfService http://swagger.io/terms/

	// @contact.name API Support
	// @contact.url http://www.swagger.io/support
	// @contact.email support@swagger.io

	// @license.name Apache 2.0
	// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

	// @host honeynet.ubiwhere.com
	// @BasePath api/v1



	/*v1 := r.Group("api/v1")
	{
			sessions := v1.Group("/sessions")
			{
				sessions.GET("", listSessions)

			}

	}*/


	authorized.GET("/sessions", listSessions)
	authorized.GET("/sessions/count", countSessions)
	authorized.GET("/sessions/statistics", listSessionStatistics)
	authorized.GET("/sessions/purge", epSessionsPrune)
	authorized.GET("/session/:session-id", epSessions)



	r.GET("/events", epEventsFind)
	r.GET("/event/:event-id", epEventGet)

	url := ginSwagger.URL("http://localhost:8080/swagger/doc.json") // The url pointing to API definition
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))

	//r.GET("/ssh/sessions", endpointSSHSessions)
	//r.GET("/ssh/session/:session_id", endpointSSHSessions)


	return r
}


// ListSessions godoc
// @Summary List sessions
// @Description get sessions
// @Tags sessions
// @Accept  json
// @Produce  json
// @Param q query string false "name search by q" Format(email)
// @Router /sessions [get]
func listSessions(c *gin.Context) {

	query, limit, sortFields := composeSessionsQuery(c)
	log.Debugf("Query: %v", query)

	list, err := sessionModel.Find(query, limit, sortFields...)
	log.Debugf("ENDPOINT /sessions (size: %v)", len(list))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Find error", "error": err.Error()})
		c.Abort()
	} else {
		c.JSON(http.StatusOK, gin.H{"sessions": list})
	}
}

func countSessions(c *gin.Context) {

	query, _, _ := composeSessionsQuery(c)
	log.Debugf("Query: %v", query)

	list, err := sessionModel.Find(query, 0)
	log.Debugf("ENDPOINT /sessions/count (size: %v)", len(list))

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Find error", "error": err.Error()})
		c.Abort()
	} else {
		c.JSON(http.StatusOK, gin.H{"total-sessions": len(list)})
	}
}

func composeSessionsQuery(c *gin.Context) (bson.M, int, []string) {
	query := bson.M{}

	creationDateInterval := false
	updateDateInterval := false
	var sortFields []string
	limit := 0 //no limit

	for k, _ := range  c.Request.URL.Query() {
		log.Debugf("key: %v", k)
		switch {
		case k == "service" || k == "source-ip" || k == "destination-ip":
			query[k] = c.Query(k)

		case k == "source-port" || k == "destination-port" || k == "event-count" || k == "creation-date" || k == "update-date":
			query[k], _ = strconv.Atoi(c.Query(k))

		case strings.HasPrefix(k, "creation-date") && !creationDateInterval:
			creationDateMap := c.QueryMap("creation-date")
			query["creation-date"] = createBSONDateInterval(creationDateMap["from"], creationDateMap["to"])
			creationDateInterval = true

		case strings.HasPrefix(k, "update-date") && !updateDateInterval:
			updateDateMap := c.QueryMap("update-date")
			query["update-date"] = createBSONDateInterval(updateDateMap["from"], updateDateMap["to"])
			updateDateInterval = true

		case k == "sort":
			sortFields = append(sortFields, c.Query(k))

		case k == "limit":
			limit, _ = strconv.Atoi(c.Query(k))
		}

	}
	return query, limit, sortFields
}

func composeStatisticsQuery(c *gin.Context) (bson.M, string) {
	query := bson.M{}
	span := "days"
	creationDateInterval := false
	updateDateInterval := false

	for k, _ := range c.Request.URL.Query() {
		switch {

		case k == "span":
			span = c.Query(k)

		case strings.HasPrefix(k, "creation-date") && !creationDateInterval:
		creationDateMap := c.QueryMap("creation-date")
		query["creation-date"] = createBSONDateInterval(creationDateMap["from"], creationDateMap["to"])
		creationDateInterval = true

		case strings.HasPrefix(k, "update-date") && !updateDateInterval:
		updateDateMap := c.QueryMap("update-date")
		query["update-date"] = createBSONDateInterval(updateDateMap["from"], updateDateMap["to"])
		updateDateInterval = true
		}
	}

	return query, span
}

func createBSONDateInterval(from string, to string) bson.M {
	interval := bson.M{}
	fromNumber, err := strconv.Atoi(from)
	if err == nil {
		interval["$gte"] = fromNumber
	}
	toNumber, err := strconv.Atoi(to)
	if err == nil {
		interval["$lte"] = toNumber
	}
	return interval

}

/*
func epSessionsSSH(c *gin.Context) {
	// var sshSessions []Session
	sshSessions := make([]models.Session, 0, 0)
	sessions := getSessionsValues()
	for _, s := range sessions {
		if s.Service == "ssh" {
			sshSessions = append(sshSessions, s)go g
		}
	}
	log.Debugf("ENDPOINT /sessions/ssh (size: %v)", len(sshSessions))
	c.JSON(http.StatusOK, sshSessions)
}

func epSessionsTelnet(c *gin.Context) {
	telnetSessions := make([]models.Session, 0, 0)
	sessions := getSessionsValues()
	for _, s := range sessions {
		if s.Service == "telnet" {
			telnetSessions = append(telnetSessions, s)
		}
	}
	log.Debugf("ENDPOINT /sessions/telnet (size: %v)", len(telnetSessions))
	c.JSON(http.StatusOK, telnetSessions)
}
*/


func epSessions(c *gin.Context) {
	sessionID := c.Params.ByName("session-id")
	log.Debugf("ENDPOINT /sessions/%v", sessionID)
	if session, ok := Sessions[sessionID]; !ok {
		c.JSON(http.StatusOK, gin.H{})
		return
	} else {
		c.JSON(http.StatusOK, session)
	}
}

func epSessionsPrune(c *gin.Context) {
	log.Debugf("ENDPOINT /sessions/prune")
	err := sessionModel.DropAll()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message:": "Couldn't remove all sessions", "error": err})
		c.Abort()
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "All sessions were removed successfully"})
	}

}

func epEventsFind(c *gin.Context) {
	list, err := eventModel.Find()
	log.Debugf("ENDPOINT /events (size: %v)", len(list))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Find error", "error": err.Error()})
		c.Abort()
	} else {
		c.JSON(http.StatusOK, gin.H{"data": list})
	}
}

func epEventGet(c *gin.Context) {
	eventID := c.Params.ByName("event-id")
	log.Debugf("ENDPOINT /events/%v", eventID)
	event, err := eventModel.Get(eventID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Event not found", "error": err.Error()})
		c.Abort()
	} else {
		c.JSON(http.StatusOK, gin.H{"data": event})
	}
}

func epEvent(c *gin.Context) {
	eventID := c.Params.ByName("event-id")
	log.Debugf("ENDPOINT /event/%v", eventID)

	if event, ok := Events[eventID]; !ok {
		c.JSON(http.StatusOK, gin.H{})
		return
	} else {
		c.JSON(http.StatusOK, event)
	}
}

func listSessionStatistics(c *gin.Context) {

	log.Debugf("Statistics endpoint")

	query, span := composeStatisticsQuery(c)
	log.Debugf("#0")

	sessions, err := sessionModel.Find(query, 0, "creation-date")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message:": "Couldn't retrieve sessions statistics", "error": err})
		c.Abort()
		return
	}
	 if len(span) == 0 || (span != "hour" && span != "day" && span != "month") {
		 c.JSON(http.StatusBadRequest, gin.H{"message:": "Invalid span. Must be one of the following: hour, day, month", "error": "bad request"})
		 c.Abort()
		 return
	 }
	log.Debugf("#1")


	if len(sessions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"message:": "No session statistics available", "error": err})
		c.Abort()
	}

	//serviceBucket := map[string][]int64[]int{}

	type  SessionStatsItem struct {
		StartDate   int64 		`json:"start-date" form:"start-date"`
		EndDate     int64 		`json:"end-date" form:"end-date"`
		Count 		int			`json:"count" form:"count"`

	}
	type  SessionStats struct {
		//Service     string     			 `json:"service" form:"service"`
		Span 		string   			 `json:"span" form:"span"`
		Items       []SessionStatsItem	 `json:"items" form:"items"`
	}

	serviceSessionStats := map[string]SessionStats{}


	prevTm := time.Unix(sessions[0].CreationDate, 0)

	log.Debugf("#2")

	var sessionStatItem SessionStatsItem

	for i, s := range sessions {

		// add service to stats if not already exists or get it
		sessionStat, ok := serviceSessionStats[s.Service]
		if !ok {
			sessionStat.Span = span
			serviceSessionStats[s.Service] = sessionStat
			log.Debugf("--> added session stat [service: %v, span: %v]", s.Service, span)
		}

		if len(sessionStat.Items) == 0 {

			sessionStatItem = SessionStatsItem{
				StartDate: s.CreationDate,
				EndDate:   0,
				Count:     0,
			}
			sessionStat.Items = append(sessionStat.Items, sessionStatItem)
			log.Debugf("--> created empty stat item for [service: %v, span: %v]", s.Service, span)
		}

		tm := time.Unix(s.CreationDate, 0)

		if AuxCompareTime(span, prevTm, tm) {
			sessionStatItem.Count += 1
			sessionStat.Items[len(sessionStat.Items)-1] = sessionStatItem
			//serviceSessionStats[s.Service] = sessionStat
			log.Debugf("--> added count for stat item [service: %v, span: %v, item: %v]", s.Service, span, sessionStatItem)

		} else {
			sessionStatItem.EndDate = sessions[i-1].CreationDate
			sessionStat.Items[len(sessionStat.Items)-1] = sessionStatItem
			//serviceSessionStats[s.Service] = sessionStat
			log.Debugf("--> closed stat item [service: %v, span: %v, item: %v]", s.Service, span, sessionStatItem)

			newSessionStateItem := SessionStatsItem{
				StartDate: s.CreationDate,
				EndDate:   0,
				Count:     1,
			}
			sessionStatItem = newSessionStateItem
			sessionStat.Items = append(sessionStat.Items, sessionStatItem)

			log.Debugf("--> added stat item [service: %v, span: %v, item: %v]", s.Service, span, sessionStatItem)
		}

		if i == len(sessions)-1 {
			sessionStatItem.EndDate = s.CreationDate
			sessionStat.Items[len(sessionStat.Items)-1] = sessionStatItem
			log.Debugf("--> closed stat item (last) [service: %v, span: %v, item: %v]", s.Service, span, sessionStatItem)
		}

		serviceSessionStats[s.Service] = sessionStat
	}


	c.JSON(http.StatusOK, gin.H{"sessions-stats": serviceSessionStats})
}

func AuxCompareTime(span string, tm1 time.Time, tm2 time.Time) bool {
	switch span {
	case "hour":
		return tm1.Hour() == tm2.Hour()
	case "day":
		return tm1.Day() == tm2.Day()
	case "month":
		return tm1.Month() == tm2.Month()
	default:
		return false
	}

}

func StartAPI() {
	r := setupRouter()
	// Listen and Serve in 0.0.0.0:8080
	r.Run(":8080")
}