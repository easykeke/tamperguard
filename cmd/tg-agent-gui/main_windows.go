//go:build windows

// TamperGuard Windows GUI client.
//
// This is the C/S client: it talks to the LocalSystem agent over the named pipe
// \\.\pipe\TamperGuardAgent, shows a window plus a tray icon, and never performs
// enforcement itself. Closing the window hides it to the tray; the service keeps
// running.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/easykeke/tamperguard/internal/ipc"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetTimer         = user32.NewProc("SetTimer")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procSetForegroundWnd = user32.NewProc("SetForegroundWindow")
	procLoadIconW        = user32.NewProc("LoadIconW")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
	procSetWindowTextW   = user32.NewProc("SetWindowTextW")
	procGetStockObject   = gdi32.NewProc("GetStockObject")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW    = shell32.NewProc("ShellExecuteW")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsVScroll          = 0x00200000
	wsTabStop          = 0x00010000
	esMultiline        = 0x0004
	esReadOnly         = 0x0800
	bsPushButton       = 0x00000000
	cwUseDefault       = 0x80000000

	wmDestroy  = 0x0002
	wmClose    = 0x0010
	wmCommand  = 0x0111
	wmTimer    = 0x0113
	wmSetText  = 0x000C
	wmSetFont  = 0x0030
	wmApp      = 0x8000
	wmTrayIcon = wmApp + 1

	swHide = 0
	swShow = 5

	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 0x00000001
	nifIcon   = 0x00000002
	nifTip    = 0x00000004
	mfString  = 0x00000000
	tpmReturn = 0x0100
	tpmRight  = 0x0002
	idiApp    = 32512
	mbOK      = 0x00000040
)

type point struct{ X, Y int32 }

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSmall  windows.Handle
}

type msg struct {
	Hwnd     windows.Handle
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type notifyIconData struct {
	Size        uint32
	Wnd         windows.Handle
	ID          uint32
	Flags       uint32
	CallbackMsg uint32
	Icon        windows.Handle
	Tip         [128]uint16
	State       uint32
	StateMask   uint32
	Info        [256]uint16
	Version     uint32
	InfoTitle   [64]uint16
	InfoFlags   uint32
	GUID        windows.GUID
	BalloonIcon windows.Handle
}

var (
	mainWnd   windows.Handle
	editWnd   windows.Handle
	trayNID   notifyIconData
	lastState ipc.Status
	haveState bool
	classes   = "TamperGuardGui"
)

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func main() {
	runtime.LockOSThread()

	mutexName := "Global\\TamperGuardGui"
	if _, err := windows.CreateMutex(nil, false, utf16(mutexName)); err == windows.ERROR_ALREADY_EXISTS {
		return
	}

	instance, _, _ := procGetModuleHandleW.Call(0)
	icon, _, _ := procLoadIconW.Call(0, idiApp)
	cursor, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512)

	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:    windows.NewCallback(wndProc),
		Instance:   windows.Handle(instance),
		Icon:       windows.Handle(icon),
		Cursor:     windows.Handle(cursor),
		Background: 6, // COLOR_WINDOW+1
		ClassName:  utf16(classes),
	}
	if atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		messageBox("注册窗口类失败: " + err.Error())
		return
	}

	hwnd, _, err := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(utf16(classes))),
		uintptr(unsafe.Pointer(utf16("TamperGuard 防护客户端"))),
		wsOverlappedWindow,
		120, 120, 620, 460,
		0, 0, instance, 0)
	if hwnd == 0 {
		messageBox("创建窗口失败: " + err.Error())
		return
	}
	mainWnd = windows.Handle(hwnd)

	font, _, _ := procGetStockObject.Call(17) // DEFAULT_GUI_FONT

	editWnd = createControl("EDIT", "",
		wsChild|wsVisible|wsVScroll|esMultiline|esReadOnly, 16, 16, 570, 330)

	createButton("打开管理端", 1, 16, 360, 130, 34)
	createButton("刷新状态", 2, 156, 360, 110, 34)
	createButton("隐藏到托盘", 3, 276, 360, 120, 34)
	createButton("退出客户端", 4, 406, 360, 120, 34)

	for _, h := range []windows.Handle{editWnd} {
		procSendMessageW.Call(uintptr(h), wmSetFont, font, 1)
	}

	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)

	initTray()
	procSetTimer.Call(hwnd, 1, 5000, 0)
	refresh()

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) == -1 || ret == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func createControl(class, text string, style uint32, x, y, w, h int32) windows.Handle {
	hwnd, _, _ := procCreateWindowExW.Call(
		0x00000200, // WS_EX_CLIENTEDGE
		uintptr(unsafe.Pointer(utf16(class))),
		uintptr(unsafe.Pointer(utf16(text))),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(mainWnd), 0, 0, 0)
	return windows.Handle(hwnd)
}

func createButton(text string, id int, x, y, w, h int32) windows.Handle {
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16("BUTTON"))),
		uintptr(unsafe.Pointer(utf16(text))),
		wsChild|wsVisible|wsTabStop|bsPushButton,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(mainWnd), uintptr(id), 0, 0)
	font, _, _ := procGetStockObject.Call(17)
	procSendMessageW.Call(hwnd, wmSetFont, font, 1)
	return windows.Handle(hwnd)
}

func wndProc(hwnd, message, wparam, lparam uintptr) uintptr {
	switch message {
	case wmCommand:
		switch int(wparam & 0xffff) {
		case 1:
			openConsole()
		case 2:
			refresh()
		case 3:
			procShowWindow.Call(hwnd, swHide)
		case 4:
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case wmTimer:
		refresh()
		return 0
	case wmTrayIcon:
		switch int(lparam & 0xffff) {
		case wmRButtonUp:
			lastTrayClick = lparam
			showTrayMenu(hwnd)
		case wmLButtonDblClk:
			procShowWindow.Call(hwnd, swShow)
			procSetForegroundWnd.Call(hwnd)
		}
		return 0
	case wmClose:
		procShowWindow.Call(hwnd, swHide)
		return 0
	case wmDestroy:
		trayNID.Flags = 0
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&trayNID)))
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, message, wparam, lparam)
	return ret
}

func initTray() {
	trayNID = notifyIconData{
		Wnd:         mainWnd,
		ID:          1,
		Flags:       nifMsg | nifIcon | nifTip,
		CallbackMsg: wmTrayIcon,
	}
	icon, _, _ := procLoadIconW.Call(0, idiApp)
	trayNID.Icon = windows.Handle(icon)
	trayNID.Size = uint32(unsafe.Sizeof(trayNID))
	setTip("TamperGuard：正在连接服务…")
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&trayNID)))
}

func setTip(text string) {
	trayNID.Flags = nifTip
	copy(trayNID.Tip[:], windows.StringToUTF16(text))
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&trayNID)))
}

func showTrayMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	procAppendMenuW.Call(menu, mfString, 10, uintptr(unsafe.Pointer(utf16("显示窗口"))))
	procAppendMenuW.Call(menu, mfString, 11, uintptr(unsafe.Pointer(utf16("打开管理端"))))
	procAppendMenuW.Call(menu, mfString, 12, uintptr(unsafe.Pointer(utf16("刷新状态"))))
	procAppendMenuW.Call(menu, mfString, 13, uintptr(unsafe.Pointer(utf16("退出客户端"))))
	procSetForegroundWnd.Call(hwnd)
	x := int32(lparamX(lastTrayClick))
	y := int32(lparamY(lastTrayClick))
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmReturn|tpmRight, uintptr(x), uintptr(y), 0, hwnd, 0)
	switch cmd {
	case 10:
		procShowWindow.Call(hwnd, swShow)
		procSetForegroundWnd.Call(hwnd)
	case 11:
		openConsole()
	case 12:
		refresh()
	case 13:
		procDestroyWindow.Call(hwnd)
	}
}

var lastTrayClick uintptr

func lparamX(l uintptr) int32 { return int32(int16(l & 0xffff)) }
func lparamY(l uintptr) int32 { return int32(int16((l >> 16) & 0xffff)) }

func refresh() {
	st, err := queryStatus()
	if err != nil {
		haveState = false
		setEdit("无法连接 TamperGuard 服务。\r\n\r\n" +
			"可能原因：服务未安装、未启动，或客户端与服务版本不一致。\r\n" +
			"错误：" + err.Error())
		setTip("TamperGuard：服务未运行")
		return
	}
	haveState = true
	lastState = st
	age := time.Now().Unix() - st.LastHeartbeat
	mode := "正常"
	if st.Degraded {
		mode = "降级（检测/回滚）"
	}
	text := fmt.Sprintf("状态：在线\r\nAgent ID：%s\r\n角色：%s\r\n版本：%s\r\n"+
		"执行层：%s\r\n运行模式：%s\r\n策略摘要：%s\r\n管理端：%s\r\n"+
		"最后心跳：%s（%d 秒前）",
		st.AgentID, st.Role, st.Version, st.Enforcer, mode,
		short(st.PolicyDigest), st.ServerURL,
		time.Unix(st.LastHeartbeat, 0).Format("2006-01-02 15:04:05"), age)
	setEdit(text)
	setTip(fmt.Sprintf("TamperGuard：在线 / %s / %s", st.Enforcer, mode))
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	if s == "" {
		return "—"
	}
	return s
}

func setEdit(text string) {
	if editWnd == 0 {
		return
	}
	procSetWindowTextW.Call(uintptr(editWnd), uintptr(unsafe.Pointer(utf16(text))))
}

func openConsole() {
	if !haveState || lastState.ServerURL == "" {
		messageBox("尚未注册：没有可用的管理端地址。")
		return
	}
	procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(utf16("open"))),
		uintptr(unsafe.Pointer(utf16(lastState.ServerURL))),
		0, 0, swShow)
}

func messageBox(text string) {
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))),
		uintptr(unsafe.Pointer(utf16("TamperGuard"))), mbOK)
}

func queryStatus() (ipc.Status, error) {
	var st ipc.Status
	name, err := windows.UTF16PtrFromString(ipc.PipeName)
	if err != nil {
		return st, err
	}
	h, err := windows.CreateFile(name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return st, err
	}
	f := os.NewFile(uintptr(h), "pipe")
	defer f.Close()
	if _, err := f.Write([]byte("{\"cmd\":\"status\"}\n")); err != nil {
		return st, err
	}
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &st); err != nil {
		return st, err
	}
	return st, nil
}
