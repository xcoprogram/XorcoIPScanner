using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Text;
using System.Drawing.Printing;

namespace NetworkScannerApp
{
    public class NetworkScannerForm : Form
    {
        private Button btnScan;
        private ProgressBar progressBar;
        private ListView lstResults;
        private ContextMenuStrip contextMenu;
        private Label lblStatus;
        private ListView lstInterfaces;
        private TextBox txtStartIp;
        private TextBox txtEndIp;
        private Label lblStartIp;
        private Label lblEndIp;
        private Button btnExportCsv;
        private Button btnExportPdf;
        private Label lblTimer;
        private Label lblVersionText;
        private Stopwatch scanStopwatch;
        
        private CancellationTokenSource cts;
        private int totalHostsToScan;
        private int scannedHostsCount;

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        public NetworkScannerForm()
        {
            InitializeComponent();
            PopulateInterfaces();
            NetworkChange.NetworkAddressChanged += (s, e) => {
                if (!this.IsDisposed)
                    this.Invoke((MethodInvoker)PopulateInterfaces);
            };
        }

        private void InitializeComponent()
        {
            const string versionStr = "v1.0.4";
            this.Text = "Xorco IP Scanner " + versionStr;
            this.Size = new Size(1100, 700);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Icon = SystemIcons.Information;

            var topContainer = new Panel { Dock = DockStyle.Top, Height = 220, Padding = new Padding(5) };
            
            var mainSplitter = new SplitContainer 
            { 
                Dock = DockStyle.Fill, 
                BorderStyle = BorderStyle.Fixed3D
            };

            // LEFT PANEL: Interface List
            var leftPanel = mainSplitter.Panel1;
            var lblInterfaceTitle = new Label { Text = "Active Network Interfaces:", Dock = DockStyle.Top, Height = 25, Font = new Font(this.Font, FontStyle.Bold) };
            lstInterfaces = new ListView 
            { 
                Dock = DockStyle.Fill,
                View = View.Details, FullRowSelect = true, GridLines = true,
                MultiSelect = false
            };
            lstInterfaces.Columns.Add("Name", 150);
            lstInterfaces.Columns.Add("IP Address", 100);
            lstInterfaces.Columns.Add("Netmask", 100);
            lstInterfaces.Columns.Add("Gateway", 100);
            lstInterfaces.Columns.Add("DNS", -2); 
            lstInterfaces.SelectedIndexChanged += LstInterfaces_SelectedIndexChanged;
            leftPanel.Controls.Add(lstInterfaces);
            leftPanel.Controls.Add(lblInterfaceTitle);

            // RIGHT PANEL: Scan Settings
            var rightPanel = mainSplitter.Panel2;
            
            lblStartIp = new Label { Text = "Start IP:", Top = 10, Left = 10, Width = 60 };
            txtStartIp = new TextBox { Top = 7, Left = 80, Width = 120 };
            
            lblEndIp = new Label { Text = "End IP:", Top = 40, Left = 10, Width = 60 };
            txtEndIp = new TextBox { Top = 37, Left = 80, Width = 120 };

            btnScan = new Button { Text = "Scan", Top = 70, Left = 10, Width = 190, Height = 30, BackColor = Color.LightBlue };
            btnScan.Click += BtnScan_Click;

            progressBar = new ProgressBar { Top = 110, Left = 10, Width = 300, Height = 20 };
            lblStatus = new Label { Top = 135, Left = 10, Width = 300, AutoSize = true, Text = "Ready" };
            lblTimer = new Label { Top = 155, Left = 10, Width = 300, AutoSize = true, Text = "" };

            lblVersionText = new Label { Text = "Xorco IP Scanner " + versionStr, Top = 10, Left = 220, Width = 150, Font = new Font(this.Font, FontStyle.Italic), ForeColor = Color.Gray };

            btnExportCsv = new Button { Text = "Export CSV", Top = 37, Left = 320, Width = 90, Height = 25 };
            btnExportCsv.Click += (s, e) => ExportToCsv();
            
            btnExportPdf = new Button { Text = "Export PDF", Top = 70, Left = 320, Width = 90, Height = 25 };
            btnExportPdf.Click += (s, e) => ExportToPdf();

            rightPanel.Controls.Add(lblStartIp);
            rightPanel.Controls.Add(txtStartIp);
            rightPanel.Controls.Add(lblEndIp);
            rightPanel.Controls.Add(txtEndIp);
            rightPanel.Controls.Add(btnScan);
            rightPanel.Controls.Add(progressBar);
            rightPanel.Controls.Add(lblStatus);
            rightPanel.Controls.Add(lblTimer);
            rightPanel.Controls.Add(lblVersionText);
            rightPanel.Controls.Add(btnExportCsv);
            rightPanel.Controls.Add(btnExportPdf);

            topContainer.Controls.Add(mainSplitter);

            lstResults = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false
            };
            
            lstResults.Columns.Add("IP Address", 120);
            lstResults.Columns.Add("MAC Address", 130);
            lstResults.Columns.Add("Hostname", 200);
            lstResults.Columns.Add("TTL", 50);
            lstResults.Columns.Add("Open Ports (80,443,22,3389)", 200);

            lstResults.ColumnClick += LstResults_ColumnClick;
            lstResults.Sorting = SortOrder.Ascending;
            sortColumn = 0;

            this.Controls.Add(lstResults);
            this.Controls.Add(topContainer);

            // Move this to the end to ensure the distance 'sticks' after layout
            mainSplitter.SplitterDistance = 650; 

            InitializeContextMenu();
        }

        private void InitializeContextMenu()
        {
            contextMenu = new ContextMenuStrip();
            var openHttpItem = new ToolStripMenuItem("Open HTTP");
            openHttpItem.Click += (s, e) => OpenProcess(GetSelectedIp(), "http://{0}");
            
            var openHttpsItem = new ToolStripMenuItem("Open HTTPS");
            openHttpsItem.Click += (s, e) => OpenProcess(GetSelectedIp(), "https://{0}");

            var openSshItem = new ToolStripMenuItem("Open SSH");
            openSshItem.Click += (s, e) => OpenSsh(GetSelectedIp());

            var openRdpItem = new ToolStripMenuItem("Open RDP");
            openRdpItem.Click += (s, e) => OpenRdp(GetSelectedIp());

            contextMenu.Items.AddRange(new ToolStripItem[] { openHttpItem, openHttpsItem, openSshItem, openRdpItem });
            contextMenu.Opening += ContextMenu_Opening;
            lstResults.ContextMenuStrip = contextMenu;
        }

        private void ContextMenu_Opening(object sender, CancelEventArgs e)
        {
            if (lstResults.SelectedItems.Count == 0)
            {
                e.Cancel = true;
            }
        }

        private string GetSelectedIp()
        {
            if (lstResults.SelectedItems.Count > 0)
                return lstResults.SelectedItems[0].SubItems[0].Text;
            return null;
        }

        private void OpenProcess(string ip, string format)
        {
            if (string.IsNullOrEmpty(ip)) return;
            try { Process.Start(new ProcessStartInfo { FileName = string.Format(format, ip), UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show("Failed to open: " + ex.Message); }
        }

        private void OpenSsh(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            
            string username = InputBox.Show("Connect to " + ip, "Enter SSH Username", Environment.UserName);
            
            if (string.IsNullOrEmpty(username)) return;

            try 
            { 
                Process.Start(new ProcessStartInfo 
                { 
                    FileName = "cmd.exe", 
                    Arguments = string.Format("/c start ssh {0}@{1}", username, ip) 
                }); 
            }
            catch (Exception ex) { MessageBox.Show("Failed to open SSH: " + ex.Message); }
        }

        private void OpenRdp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            try { Process.Start(new ProcessStartInfo { FileName = "mstsc.exe", Arguments = string.Format("/v:{0}", ip) }); }
            catch (Exception ex) { MessageBox.Show("Failed to open RDP: " + ex.Message); }
        }

        private class InterfaceItem
        {
            public IPAddress Address { get; set; }
            public IPAddress Mask { get; set; }
            public string Name { get; set; }
            public string Gateway { get; set; }
            public string Dns { get; set; }

            public override string ToString()
            {
                return string.Format("{0} ({1})", Name, Address);
            }
        }

        private void PopulateInterfaces()
        {
            string selectedIp = null;
            if (lstInterfaces.SelectedItems.Count > 0)
                selectedIp = lstInterfaces.SelectedItems[0].SubItems[1].Text;

            lstInterfaces.Items.Clear();
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up && 
                            (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet || 
                             ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                             ni.Name.ToLower().Contains("vpn") ||
                             ni.Description.ToLower().Contains("vpn") ||
                             ni.Description.ToLower().Contains("virtual")))
                .ToList();

            foreach (var ni in interfaces)
            {
                var ipProps = ni.GetIPProperties();
                foreach (var ip in ipProps.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork && !ip.Address.ToString().StartsWith("169.254"))
                    {
                        var dnsServers = ipProps.DnsAddresses.Where(d => d.AddressFamily == AddressFamily.InterNetwork).Select(d => d.ToString());
                        var gateways = ipProps.GatewayAddresses.Where(g => g.Address.AddressFamily == AddressFamily.InterNetwork).Select(g => g.Address.ToString());
                        
                        string dnsString = string.Join(", ", dnsServers);
                        string gatewayString = string.Join(", ", gateways);

                        var item = new ListViewItem(ni.Name);
                        item.SubItems.Add(ip.Address.ToString());
                        item.SubItems.Add(ip.IPv4Mask.ToString());
                        item.SubItems.Add(gatewayString);
                        item.SubItems.Add(dnsString);
                        item.Tag = new InterfaceItem 
                        { 
                            Address = ip.Address, 
                            Mask = ip.IPv4Mask, 
                            Name = ni.Name,
                            Gateway = gatewayString,
                            Dns = dnsString
                        };
                        lstInterfaces.Items.Add(item);
                        
                        if (selectedIp != null && ip.Address.ToString() == selectedIp)
                            item.Selected = true;
                    }
                }
            }

            if (lstInterfaces.Items.Count > 0 && lstInterfaces.SelectedItems.Count == 0)
                lstInterfaces.Items[0].Selected = true;
        }

        private void LstInterfaces_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (lstInterfaces.SelectedItems.Count > 0)
            {
                var item = lstInterfaces.SelectedItems[0].Tag as InterfaceItem;
                if (item != null)
                {
                    var baseIpBytes = item.Address.GetAddressBytes();
                    var maskBytes = item.Mask.GetAddressBytes();
                    
                    var networkBytes = new byte[4];
                    var broadcastBytes = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        networkBytes[i] = (byte)(baseIpBytes[i] & maskBytes[i]);
                        broadcastBytes[i] = (byte)(networkBytes[i] | ~maskBytes[i]);
                    }

                    uint networkAddress = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);
                    uint broadcastAddress = BitConverter.ToUInt32(broadcastBytes.Reverse().ToArray(), 0);

                    txtStartIp.Text = new IPAddress(BitConverter.GetBytes(networkAddress + 1).Reverse().ToArray()).ToString();
                    txtEndIp.Text = new IPAddress(BitConverter.GetBytes(broadcastAddress - 1).Reverse().ToArray()).ToString();
                }
            }
        }

        private async void BtnScan_Click(object sender, EventArgs e)
        {
            if (btnScan.Text == "Scan")
            {
                IPAddress startIp, endIp;
                if (!IPAddress.TryParse(txtStartIp.Text, out startIp) || !IPAddress.TryParse(txtEndIp.Text, out endIp))
                {
                    MessageBox.Show("Please enter valid start and end IP addresses.");
                    return;
                }

                lstResults.Items.Clear();
                btnScan.Text = "Stop";
                progressBar.Value = 0;
                lblTimer.Text = "Estimating time...";
                scanStopwatch = Stopwatch.StartNew();
                cts = new CancellationTokenSource();

                byte[] startBytes = startIp.GetAddressBytes().Reverse().ToArray();
                byte[] endBytes = endIp.GetAddressBytes().Reverse().ToArray();
                
                uint startAddr = BitConverter.ToUInt32(startBytes, 0);
                uint endAddr = BitConverter.ToUInt32(endBytes, 0);

                if (startAddr > endAddr)
                {
                    MessageBox.Show("Start IP cannot be greater than end IP.");
                    btnScan.Text = "Scan";
                    return;
                }

                totalHostsToScan = (int)(endAddr - startAddr + 1);
                
                if (totalHostsToScan > 65536)
                {
                    if (MessageBox.Show(string.Format("You are about to scan {0} hosts. This may take a long time. Continue?", totalHostsToScan), "Large Scan Area", MessageBoxButtons.YesNo) == DialogResult.No)
                    {
                        btnScan.Text = "Scan";
                        return;
                    }
                }

                progressBar.Maximum = totalHostsToScan;
                scannedHostsCount = 0;
                lblStatus.Text = string.Format("Scanning {0} hosts...", totalHostsToScan);

                var ipsToScan = new List<IPAddress>();
                for (uint i = startAddr; i <= endAddr; i++)
                {
                    byte[] bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                    ipsToScan.Add(new IPAddress(bytes));
                }

                try
                {
                    await Task.Run(() => PerformScan(ipsToScan, cts.Token));
                }
                catch (OperationCanceledException) { }
                finally
                {
                    scanStopwatch.Stop();
                    btnScan.Text = "Scan";
                    progressBar.Value = progressBar.Maximum;
                    lblStatus.Text = "Scan Complete";
                    lblTimer.Text = string.Format("Total time: {0:mm\\:ss}", scanStopwatch.Elapsed);
                    
                    // Final sort after scan
                    this.Invoke((MethodInvoker)delegate {
                        lstResults.ListViewItemSorter = new ListViewItemComparer(sortColumn, lstResults.Sorting);
                        lstResults.Sort();
                    });
                }
            }
            else
            {
                if (cts != null) cts.Cancel();
                btnScan.Text = "Scan";
                lblStatus.Text = "Cancelled";
            }
        }

        private void PerformScan(List<IPAddress> ips, CancellationToken token)
        {
            var options = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount * 20, CancellationToken = token };
            
            try
            {
                Parallel.ForEach(ips, options, ip =>
                {
                    token.ThrowIfCancellationRequested();
                    ScanIp(ip);
                    Interlocked.Increment(ref scannedHostsCount);
                    UpdateProgress();
                });
            }
            catch (OperationCanceledException) { }
        }

        private void UpdateProgress()
        {
            this.Invoke((MethodInvoker)delegate
            {
                if (scannedHostsCount <= progressBar.Maximum)
                {
                    progressBar.Value = scannedHostsCount;
                    lblStatus.Text = string.Format("{0} / {1}", scannedHostsCount, totalHostsToScan);
                    
                    if (scannedHostsCount > 0)
                    {
                        var elapsed = scanStopwatch.Elapsed.TotalSeconds;
                        var hostsPerSecond = scannedHostsCount / elapsed;
                        var remainingHosts = totalHostsToScan - scannedHostsCount;
                        var remainingSeconds = remainingHosts / hostsPerSecond;
                        
                        var timeSpan = TimeSpan.FromSeconds(remainingSeconds);
                        lblTimer.Text = string.Format("Estimated remaining: {0:mm\\:ss}", timeSpan);
                    }
                }
            });
        }

        private void ScanIp(IPAddress ip)
        {
            try
            {
                var ping = new Ping();
                var reply = ping.Send(ip, 750); // 750ms timeout

                // ARP Fallback to handle non-pingable hosts in same subnet
                string macAddress = GetMacAddress(ip);
                bool isAlive = (reply.Status == IPStatus.Success) || (macAddress != "Unknown");

                if (isAlive)
                {
                    var hostname = GetHostname(ip);
                    var openPorts = ScanPorts(ip);
                    string ttl = reply.Options != null ? reply.Options.Ttl.ToString() : "-";

                    this.Invoke((MethodInvoker)delegate
                    {
                        var item = new ListViewItem(ip.ToString());
                        item.SubItems.Add(macAddress);
                        item.SubItems.Add(hostname);
                        item.SubItems.Add(ttl);
                        item.SubItems.Add(openPorts);
                        lstResults.Items.Add(item);
                    });
                }
            }
            catch { }
        }

        private string GetMacAddress(IPAddress ipAddress)
        {
            byte[] macAddr = new byte[6];
            uint macAddrLen = (uint)macAddr.Length;

            int destIP = BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0);
            
            if (SendARP(destIP, 0, macAddr, ref macAddrLen) == 0)
            {
                string[] str = new string[(int)macAddrLen];
                for (int i = 0; i < macAddrLen; i++)
                    str[i] = macAddr[i].ToString("X2");
                return string.Join(":", str);
            }
            return "Unknown";
        }

        private string GetHostname(IPAddress ip)
        {
            try
            {
                var entry = Dns.GetHostEntry(ip);
                return entry.HostName;
            }
            catch
            {
                return "";
            }
        }

        private string ScanPorts(IPAddress ip)
        {
            int[] ports = { 80, 443, 22, 3389 };
            var openPorts = new List<int>();

            Parallel.ForEach(ports, port =>
            {
                try
                {
                    using (var client = new TcpClient())
                    {
                        var result = client.BeginConnect(ip, port, null, null);
                        var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(500));
                        if (success)
                        {
                            client.EndConnect(result);
                            lock (openPorts) { openPorts.Add(port); }
                        }
                    }
                }
                catch { }
            });

            openPorts.Sort();
            return string.Join(", ", openPorts);
        }

        private void ExportToCsv()
        {
            if (lstResults.Items.Count == 0) { MessageBox.Show("No results to export."); return; }
            
            using (var sfd = new SaveFileDialog { Filter = "CSV Files|*.csv", FileName = "network_scan_results.csv" })
            {
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("IP Address,MAC Address,Hostname,TTL,Open Ports");
                    foreach (ListViewItem item in lstResults.Items)
                    {
                        var line = string.Format("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\"",
                            item.SubItems[0].Text, item.SubItems[1].Text, item.SubItems[2].Text,
                            item.SubItems[3].Text, item.SubItems[4].Text);
                        sb.AppendLine(line);
                    }
                    File.WriteAllText(sfd.FileName, sb.ToString());
                    MessageBox.Show("Exported successfuly to " + sfd.FileName);
                }
            }
        }

        private void ExportToPdf()
        {
            if (lstResults.Items.Count == 0) { MessageBox.Show("No results to export."); return; }

            using (var sfd = new SaveFileDialog { Filter = "PDF Files|*.pdf", FileName = "network_scan_results.pdf" })
            {
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        var doc = new PrintDocument();
                        doc.PrinterSettings.PrinterName = "Microsoft Print to PDF";
                        doc.PrinterSettings.PrintToFile = true;
                        doc.PrinterSettings.PrintFileName = sfd.FileName;

                        int itemIndex = 0;
                        doc.PrintPage += (s, ev) =>
                        {
                            float yPos = 50;
                            var font = new Font("Arial", 10);
                            var headerFont = new Font("Arial", 12, FontStyle.Bold);
                            
                            ev.Graphics.DrawString("Network Scan Results - " + DateTime.Now.ToString(), headerFont, Brushes.Black, 50, yPos);
                            yPos += 40;

                            // Draw Headers
                            ev.Graphics.DrawString("IP Address", headerFont, Brushes.Black, 50, yPos);
                            ev.Graphics.DrawString("MAC", headerFont, Brushes.Black, 180, yPos);
                            ev.Graphics.DrawString("Hostname", headerFont, Brushes.Black, 330, yPos);
                            ev.Graphics.DrawString("Ports", headerFont, Brushes.Black, 580, yPos);
                            yPos += 30;
                            ev.Graphics.DrawLine(Pens.Black, 50, yPos, 750, yPos);
                            yPos += 10;

                            while (itemIndex < lstResults.Items.Count)
                            {
                                var item = lstResults.Items[itemIndex];
                                ev.Graphics.DrawString(item.SubItems[0].Text, font, Brushes.Black, 50, yPos);
                                ev.Graphics.DrawString(item.SubItems[1].Text, font, Brushes.Black, 180, yPos);
                                ev.Graphics.DrawString(item.SubItems[2].Text, font, Brushes.Black, 330, yPos);
                                ev.Graphics.DrawString(item.SubItems[4].Text, font, Brushes.Black, 580, yPos);
                                
                                yPos += 20;
                                itemIndex++;

                                if (yPos > ev.MarginBounds.Bottom)
                                {
                                    ev.HasMorePages = true;
                                    return;
                                }
                            }
                            ev.HasMorePages = false;
                        };

                        doc.Print();
                        MessageBox.Show("Exported successfuly to " + sfd.FileName);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("PDF Export failed: " + ex.Message + "\nEnsure 'Microsoft Print to PDF' is installed.");
                    }
                }
            }
        }

        private int sortColumn = 0;
        private void LstResults_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            if (e.Column != sortColumn)
            {
                sortColumn = e.Column;
                lstResults.Sorting = SortOrder.Ascending;
            }
            else
            {
                if (lstResults.Sorting == SortOrder.Ascending)
                    lstResults.Sorting = SortOrder.Descending;
                else
                    lstResults.Sorting = SortOrder.Ascending;
            }

            lstResults.Sort();
            lstResults.ListViewItemSorter = new ListViewItemComparer(e.Column, lstResults.Sorting);
        }

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new NetworkScannerForm());
        }
    }

    class ListViewItemComparer : System.Collections.IComparer
    {
        private int col;
        private SortOrder order;

        public ListViewItemComparer(int column, SortOrder order)
        {
            col = column;
            this.order = order;
        }

        public int Compare(object x, object y)
        {
            int returnVal = 0;
            var itemX = ((ListViewItem)x).SubItems[col].Text;
            var itemY = ((ListViewItem)y).SubItems[col].Text;
            
            // Try IP Address sorting (Column 0)
            if (col == 0)
            {
                IPAddress ipX, ipY;
                if (IPAddress.TryParse(itemX, out ipX) && IPAddress.TryParse(itemY, out ipY))
                {
                    byte[] bytesX = ipX.GetAddressBytes();
                    byte[] bytesY = ipY.GetAddressBytes();
                    for(int i = 0; i < bytesX.Length && i < bytesY.Length; i++)
                    {
                        if(bytesX[i] != bytesY[i])
                        {
                            returnVal = bytesX[i].CompareTo(bytesY[i]);
                            break;
                        }
                    }
                }
                else
                {
                    returnVal = String.Compare(itemX, itemY);
                }
            }
            // Parse TTL sorting (Column 3)
            else if (col == 3)
            {
                int vx, vy;
                int valX = int.TryParse(itemX, out vx) ? vx : 0;
                int valY = int.TryParse(itemY, out vy) ? vy : 0;
                returnVal = valX.CompareTo(valY);
            }
            else
            {
                returnVal = String.Compare(itemX, itemY);
            }

            if (order == SortOrder.Descending)
                returnVal *= -1;

            return returnVal;
        }
    }

    public static class InputBox
    {
        public static string Show(string prompt, string title, string defaultValue = "")
        {
            Form form = new Form();
            Label label = new Label();
            TextBox textBox = new TextBox();
            Button buttonOk = new Button();
            Button buttonCancel = new Button();

            form.Text = title;
            label.Text = prompt;
            textBox.Text = defaultValue;

            buttonOk.Text = "OK";
            buttonCancel.Text = "Cancel";
            buttonOk.DialogResult = DialogResult.OK;
            buttonCancel.DialogResult = DialogResult.Cancel;

            label.SetBounds(9, 20, 372, 13);
            textBox.SetBounds(12, 45, 372, 20);
            buttonOk.SetBounds(228, 80, 75, 23);
            buttonCancel.SetBounds(309, 80, 75, 23);

            label.AutoSize = true;
            textBox.Anchor = textBox.Anchor | AnchorStyles.Right;
            buttonOk.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            buttonCancel.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;

            form.ClientSize = new Size(396, 115);
            form.Controls.AddRange(new Control[] { label, textBox, buttonOk, buttonCancel });
            form.ClientSize = new Size(Math.Max(300, label.Right + 10), form.ClientSize.Height);
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.StartPosition = FormStartPosition.CenterParent;
            form.MinimizeBox = false;
            form.MaximizeBox = false;
            form.AcceptButton = buttonOk;
            form.CancelButton = buttonCancel;

            DialogResult dialogResult = form.ShowDialog();
            return (dialogResult == DialogResult.OK) ? textBox.Text : null;
        }
    }
}
