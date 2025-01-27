package debugserver

import (
	"errors"
	"io"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
	"howett.net/plist"

	log "github.com/sirupsen/logrus"
)

const (
	serviceName    = "com.apple.debugserver"
	sslServiceName = "com.apple.debugserver.DVTSecureSocketProxy"
	rsdServiceName = "com.apple.internal.dt.remote.debugproxy"
)

// original: https://github.com/steeve/itool/blob/master/debugserver/debugserver.go#L14
type DebugClient struct {
	c         io.ReadWriter
	gdbServer *GDBServer
}

func (c *DebugClient) Recv() (string, error) {
	return c.gdbServer.Recv()
}

func (c *DebugClient) Send(req string) error {
	return c.gdbServer.Send(req)
}

func (c *DebugClient) Request(req string) (string, error) {
	return c.gdbServer.Request(req)
}

func (c *DebugClient) Conn() io.ReadWriter {
	return c.c
}

// Write the script file to the tmp directory and start lldb
func startLLDB(appPath, container string, port int, stopAtEntry bool) error {
	var optionStopAtEntry string
	if stopAtEntry {
		optionStopAtEntry = STOP_AT_ENTRY
	}

	py, err := os.OpenFile(PY_PATH, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer py.Close()

	pyt, err := template.New("py").Parse(PY_FMT)
	if err != nil {
		return err
	}
	err = pyt.Execute(py, struct {
		StopAtEntry string
	}{
		StopAtEntry: optionStopAtEntry,
	})
	if err != nil {
		return err
	}

	script, err := os.OpenFile(SCRIPT_PATH, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer script.Close()

	st, err := template.New("script").Parse(LLDB_FMT)
	if err != nil {
		return err
	}
	err = st.Execute(script, struct {
		AppPath   string
		Container string
		Port      int
		PyName    string
		PyPath    string
	}{
		AppPath:   appPath,
		Container: container,
		Port:      port,
		PyName:    strings.TrimSuffix(path.Base(PY_PATH), path.Ext(PY_PATH)),
		PyPath:    PY_PATH,
	})
	if err != nil {
		return err
	}
	cmd := exec.Command(LLDB_SHELL, "-s", SCRIPT_PATH)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	return err
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func getBundleidFromApp(appPath string) (string, error) {
	plistPath := path.Join(appPath, "Info.plist")
	// check path
	if !fileExists(plistPath) {
		return "", errors.New("cannot find info.plist")
	}
	// read bundleId
	pcontent, err := os.ReadFile(plistPath)
	if err != nil {
		return "", err
	}
	pmap := make(map[string]interface{})
	_, err = plist.Unmarshal(pcontent, pmap)
	if err != nil {
		return "", err
	}

	bundleId, ok := pmap["CFBundleIdentifier"]
	if !ok || bundleId == nil {
		return "", errors.New("cannot find CFBundleIdentifier in Info.plist")
	}
	return bundleId.(string), nil
}

func connectToDevice(device ios.DeviceEntry) (ios.DeviceConnectionInterface, error) {
	info, err := ios.GetValuesPlist(device)
	if err != nil {
		return nil, err
	}
	version, ok := info["ProductVersion"]
	if !ok {
		log.Error("cannot find version, default use ssl debug server")
		return ios.ConnectToService(device, sslServiceName)
	}
	if version.(string) >= "17" {
		return nil, nil
	}
	if version.(string) > "14" {
		return ios.ConnectToService(device, sslServiceName)
	}
	intf, err := ios.ConnectToService(device, serviceName)
	if err != nil {
		return intf, err
	}
	return intf, err
}

func Start(device ios.DeviceEntry, appPath string, stopAtEntry bool) error {
	bundleId, err := getBundleidFromApp(appPath)
	if err != nil {
		return err
	}
	conn, err := installationproxy.New(device)
	if err != nil {
		return err
	}
	appinfo, err := conn.BrowseUserApps()
	if err != nil {
		return err
	}
	var container string
	for _, ai := range appinfo {
		if (ai.CFBundleIdentifier == bundleId ||
			strings.HasPrefix(ai.CFBundleIdentifier, bundleId + ".")) {
			container = ai.Path
			break
		}
	}
	if container == "" {
		return errors.New("cannot find container of bundleid: " + bundleId)
	}

	intf, err := connectToDevice(device)
	if err != nil {
		return err
	}
	// listen at random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	log.Info("debug proxy listen port: ", port)
	go func() {
		time.Sleep(time.Second)
		err := startLLDB(appPath, container, port, stopAtEntry)
		if err != nil {
			log.Fatal(err)
		} else {
			// exit without error
			log.Exit(0)
		}
	}()
	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Error(err)
			continue
		}
		go func() {
			var remoteConn io.ReadWriter
			if intf != nil {
				remoteConn = ios.NewLockDownConnection(intf).Conn()
			} else {
				lc, err := ios.ConnectToServiceTunnelIface(device, rsdServiceName)
				if err != nil {
					log.Error(err)
					return
				}
				defer lc.Close()
				remoteConn = lc
			}
			cli := &DebugClient{
				c:         remoteConn,
				gdbServer: NewGDBServer(remoteConn),
			}
			// start proxy
			go io.Copy(localConn, cli.Conn())
			io.Copy(cli.Conn(), localConn)
		}()
	}
}

func AttachAndDetach(device ios.DeviceEntry, pid uint64) error {
	intf, err := connectToDevice(device)
	if err != nil {
		return err
	}
	var conn io.ReadWriter
	if intf != nil {
		conn = ios.NewLockDownConnection(intf).Conn()
	} else {
		lc, err := ios.ConnectToServiceTunnelIface(device, rsdServiceName)
		if err != nil {
			return err
		}
		defer lc.Close()
		conn = lc
	}

	gdbServer := NewGDBServer(conn)

	reply, err := gdbServer.Request("QSetDetachOnError:1")
	log.Debug("SetDetachOnError: ", reply)
	if err != nil {
		return err
	} else if !strings.HasPrefix(reply, "OK") {
		return errors.New("failed to SetDetachOnError")
	}

	reply, err = gdbServer.Request(fmt.Sprintf("vAttach;%x", pid))
	log.Debug("Attach: ", reply)
	if err != nil {
		return err
	} else if !strings.HasPrefix(reply, "T11thread") {
		return errors.New("failed to attach the process")
	}

	reply, err = gdbServer.Request("D")
	log.Debug("Detach: ", reply)
	if err != nil {
		return err
	} else if !strings.HasPrefix(reply, "OK") {
		return errors.New("failed to detach the process")
	}
	return nil
}
