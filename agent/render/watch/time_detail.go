package watch

import (
	"cmp"
	"fmt"
	"kyanos/agent/analysis/common"
	c "kyanos/common"
	"slices"
	"strings"

	"github.com/Ha4sh-447/flowcharts/diagrams"
	"github.com/Ha4sh-447/flowcharts/draw"
)

func ViewRecordTimeDetailAsFlowChart(r *common.AnnotatedRecord) (result string) {
	defer func() {
		if err := recover(); err != nil {
			c.DefaultLog.Errorln(err)
			result = r.TimeDetailInfo()
		}
	}()
	if r.Side == c.ServerSide {
		result = ViewRecordTimeDetailAsFlowChartForServer(r)
	} else {
		result = ViewRecordTimeDetailAsFlowChartForClientSide(r)
	}
	return result
}

func addNicEventsDiagram(events []common.NicEventDetail, prevNicArrow *diagrams.Shape, prevTs int64, shapes *[]*diagrams.Shape, isReq bool) (*diagrams.Shape, int64) {
	var arrowType diagrams.ShapeType
	var connectFunc func(shape *diagrams.Shape, subShape *diagrams.Shape)
	var lastShape *diagrams.Shape
	if isReq {
		arrowType = diagrams.RightArrow
		connectFunc = diagrams.AddToRight
	} else {
		arrowType = diagrams.LeftArrow
		connectFunc = diagrams.AddToLeft
	}
	nicEvents := nicEventDetailsAsNicEvents(events)
	for idx, nicEvent := range nicEvents {
		var nicShapeContent string
		if prevTs > 0 {
			nicShapeContent = fmt.Sprintf(" %s(used:%.2fms)", nicEvent.ifname, c.ConvertDurationToMillisecondsIfNeeded(float64(nicEvent.ts-int64(prevTs)), false))
		} else {
			nicShapeContent = fmt.Sprintf(" %s ", nicEvent.ifname)
		}
		nicShape := diagrams.Shape{
			Content:    nicShapeContent,
			Type:       diagrams.Rectangle,
			IsJunction: true,
		}
		if prevNicArrow != nil {
			if isReq || idx > 0 || prevNicArrow.Type != diagrams.DownArrow {
				connectFunc(prevNicArrow, &nicShape)
			} else {
				// 第一个响应到达网卡
				diagrams.AddToBottom(prevNicArrow, &nicShape)
			}

			*shapes = append(*shapes, prevNicArrow)
		}
		*shapes = append(*shapes, &nicShape)

		if idx != len(nicEvents)-1 {
			nicToNext := diagrams.Shape{
				Content: fmt.Sprintf("%s to next", nicEvent.ifname),
				Type:    arrowType,
			}
			connectFunc(&nicShape, &nicToNext)
			// *shapes = append(*shapes, nicToNext)
			prevNicArrow = &nicToNext
		} else {
			// nicShape.IsLast = true
		}
		lastShape = &nicShape
		prevTs = nicEvent.ts

	}
	if len(nicEvents) > 0 {
		return lastShape, nicEvents[len(nicEvents)-1].ts
	} else {
		return lastShape, 0
	}
}

func addSocketBufferDiagram(duration int64, prevDiagram *diagrams.Shape, shapes *[]*diagrams.Shape, isReq bool) *diagrams.Shape {
	var arrowType diagrams.ShapeType
	var connectFunc func(shape *diagrams.Shape, subShape *diagrams.Shape)
	if isReq {
		arrowType = diagrams.RightArrow
		connectFunc = diagrams.AddToRight
	} else {
		arrowType = diagrams.LeftArrow
		connectFunc = diagrams.AddToLeft
	}
	lastNicToSocketArrow := diagrams.Shape{
		Content: "",
		Type:    arrowType,
	}
	connectFunc(prevDiagram, &lastNicToSocketArrow)
	socketBuffer := diagrams.Shape{
		Content: fmt.Sprintf(" Socket(used:%.2fms) ",
			c.ConvertDurationToMillisecondsIfNeeded(float64(duration), false)),
		Type: diagrams.Rectangle,
	}
	connectFunc(&lastNicToSocketArrow, &socketBuffer)
	socketToAppArrow := diagrams.Shape{
		Content: "",
		Type:    arrowType,
	}
	connectFunc(&socketBuffer, &socketToAppArrow)
	defer func() {
		*shapes = append(*shapes, &lastNicToSocketArrow, &socketBuffer)
	}()
	return &socketToAppArrow
}

func getFlowChartString(diagram *diagrams.Diagram) string {
	s := diagrams.NewStore()
	canvasRow := 200
	canvas := draw.NewCanvas(canvasRow, canvasRow)
	canvas.Cursor.X = canvasRow / 4
	c.DefaultLog.Debugf("shapes: %v", diagram.S)
	for _, shape := range diagram.S {
		c.DefaultLog.Debugf("shape: %v", shape)
		diagrams.RenderD(&shape, canvas, s)
	}
	myCanvas := ToMyCanvas(canvas)

	return myCanvas.toString()
}

func ViewRecordTimeDetailAsFlowChartForServer(r *common.AnnotatedRecord) string {
	shapes := make([]*diagrams.Shape, 0)
	diagram := diagrams.New()
	lastNicShape, _ := addNicEventsDiagram(r.ReqNicEventDetails, nil, 0, &shapes, true)
	socketToAppArrow := addSocketBufferDiagram(int64(r.CopyToSocketBufferDuration), lastNicShape, &shapes, true)
	shapes = append(shapes, socketToAppArrow)
	applicationStart := diagrams.Shape{
		Content: fmt.Sprintf(" Process(used:%.2fms) ", c.ConvertDurationToMillisecondsIfNeeded(r.ReadFromSocketBufferDuration, false)),
		Type:    diagrams.Rectangle,
	}
	diagrams.AddToRight(socketToAppArrow, &applicationStart)
	shapes = append(shapes, &applicationStart)

	appStartToAppEndArrow := diagrams.Shape{
		Content: "lastNicToBottomArrow",
		Type:    diagrams.DownArrow,
	}
	shapes = append(shapes, &appStartToAppEndArrow)

	applicationEnd := diagrams.Shape{
		Content: fmt.Sprintf(" Process(used:%.2fms) ", c.ConvertDurationToMillisecondsIfNeeded(r.BlackBoxDuration, false)),
		Type:    diagrams.Rectangle,
	}
	shapes = append(shapes, &applicationEnd)
	diagrams.AddToBottom(&applicationStart, &appStartToAppEndArrow)

	appEndToNic0Arrow := diagrams.Shape{
		Content: "appEndToNic0Arrow",
		Type:    diagrams.LeftArrow,
	}
	diagrams.AddToLeft(&applicationEnd, &appEndToNic0Arrow)
	// shapes = append(shapes, &appEndToNic0Arrow)
	addNicEventsDiagram(r.RespNicEventDetails, &appEndToNic0Arrow, r.GetLastRespSyscallTime(), &shapes, false)
	for _, shape := range shapes {
		diagram.AddShapes(*shape)
	}
	return getFlowChartString(diagram)
}

func ViewRecordTimeDetailAsFlowChartForClientSide(r *common.AnnotatedRecord) string {
	shapes := make([]*diagrams.Shape, 0)
	diagram := diagrams.New()
	applicationStart := diagrams.Shape{
		Content: fmt.Sprintf(" Process(pid:%d) ", r.Pid),
		Type:    diagrams.Rectangle,
	}
	appToNic0 := diagrams.Shape{
		Content: "",
		Type:    diagrams.RightArrow,
		// IsJunction: true,
	}
	diagrams.AddToRight(&applicationStart, &appToNic0)
	shapes = append(shapes, &applicationStart)

	lastNicShape, lastNicTs := addNicEventsDiagram(r.ReqNicEventDetails, &appToNic0, int64(r.StartTs), &shapes, true)
	lastNicToBottomArrow := diagrams.Shape{
		Content: "lastNicToBottomArrow",
		Type:    diagrams.DownArrow,
	}
	diagrams.AddToBottom(lastNicShape, &lastNicToBottomArrow)
	lastNicShape, _ = addNicEventsDiagram(r.RespNicEventDetails, &lastNicToBottomArrow, lastNicTs, &shapes, false)
	socketBufferToLeftArrow := addSocketBufferDiagram(int64(r.CopyToSocketBufferDuration), lastNicShape, &shapes, false)

	applicationEnd := diagrams.Shape{
		Content: fmt.Sprintf(" Process(used:%.2fms) ",
			c.ConvertDurationToMillisecondsIfNeeded(r.ReadFromSocketBufferDuration, false)),
		Type:   diagrams.Rectangle,
		IsLast: true,
	}
	diagrams.AddToLeft(socketBufferToLeftArrow, &applicationEnd)
	shapes = append(shapes, socketBufferToLeftArrow, &applicationEnd)

	for _, shape := range shapes {
		diagram.AddShapes(*shape)
	}
	return getFlowChartString(diagram)
}

func nicEventDetailsAsNicEvents(details []common.NicEventDetail) []nicEvent {
	events := make([]nicEvent, 0)

	eventMap := make(map[string]int64)
	for _, detail := range details {
		for key, value := range detail.Attributes {
			if ifname := strings.TrimPrefix(key, "time-"); ifname != key {
				eventMap[ifname] = value.(int64)
			}
		}
	}

	for ifname, time := range eventMap {
		events = append(events, nicEvent{ifname, time})
	}

	slices.SortFunc(events, func(e1, e2 nicEvent) int {
		return cmp.Compare(e1.ts, e2.ts)
	})
	return events
}

type nicEvent struct {
	ifname string
	ts     int64
}

// Canvas grid will be the draw area
type Canvas struct {
	Rows   int
	Cols   int
	Grid   [][]string
	Cursor Point
	Center int
}

type Point struct {
	X int
	Y int
}

func ToDrawCanvas(c *Canvas) *draw.Canvas {
	newC := draw.NewCanvas(c.Rows, c.Cols)
	newC.Grid = c.Grid
	newC.Cursor = draw.Point(c.Cursor)
	newC.Center = c.Center
	return newC
}
func ToMyCanvas(c *draw.Canvas) *Canvas {
	newC := NewCanvas(c.Rows, c.Cols)
	newC.Grid = c.Grid
	newC.Cursor = Point(c.Cursor)
	newC.Center = c.Center
	return newC
}

// Create a new canvas
func NewCanvas(r, c int) *Canvas {
	g := make([][]string, r)
	for i := range g {
		g[i] = make([]string, c)
	}
	for i := range g {
		for j := range g[i] {
			g[i][j] = " "
		}
	}

	p := Point{
		X: c/2 - 10,
		Y: 0,
	}

	return &Canvas{
		Rows:   r,
		Cols:   c,
		Grid:   g,
		Cursor: p,
	}
}

func Center(c *Canvas, x, y int) {
	c.Cursor.X = x
	c.Cursor.Y = y
}

func (c *Canvas) CenterX() {
	c.Cursor.X = 40
}

func (c *Canvas) Render() {
	c.toString()
}

func (c *Canvas) Save() {
}

func (c *Canvas) toString() string {
	grid := c.cleanGrid()
	var str strings.Builder

	// for i := range grid {
	// 	for j := range grid[0] {
	// 		fmt.Printf("%s", grid[i][j])
	// 	}
	// 	fmt.Println()
	// }

	for _, r := range grid {
		for _, c := range r {
			str.WriteString(c)
		}
		str.WriteString("\n")
	}

	return str.String()
}

func (c *Canvas) cleanGrid() [][]string {
	grid := c.Grid
	var res [][]string

	for _, r := range grid {
		str := strings.Join(r, "")
		if strings.Compare(strings.TrimSpace(str), "") != 0 {
			res = append(res, r)
		}
	}

	return res
}
