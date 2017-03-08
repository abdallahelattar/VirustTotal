using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNET;
using VirusTotalNET.DateTimeParsers;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using System.Windows.Forms;
using System.IO;
using System.Drawing;

namespace VirusTotal
{
    class Execute
    {
        private static string APIKey = "c7f33f2b81cd987ec63c37a3a18028e362e3baf2d8666013f2d0cbe7b7a707f5"; //attar's key
        
   


        public static void SetAPIKey(string key)
        {
            APIKey = key;
        }

        public static async Task ScanURL(string url, RichTextBox richtextbox, DataGridView datagridview)
        {
            try
            {
                VirusTotalNET.VirusTotal virusTotal = new VirusTotalNET.VirusTotal(APIKey);

                //Use HTTPS instead of HTTP
                virusTotal.UseTLS = true;

                UrlReport urlReport = await virusTotal.GetUrlReport(url);

                bool hasUrlBeenScannedBefore = urlReport.ResponseCode == ReportResponseCode.Present;

                //If the url has been scanned before, the results are embedded inside the report.
                if (hasUrlBeenScannedBefore)
                {
                    PrintScan(urlReport, url, hasUrlBeenScannedBefore, richtextbox, datagridview);
                }
                else
                {
                    UrlScanResult urlResult = await virusTotal.ScanUrl(url);
                    PrintScan(urlResult, url, hasUrlBeenScannedBefore, richtextbox, datagridview);
                }
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "Something went wrong!");
            }

}

        public static async Task ScanFile(string path, RichTextBox richtextbox, DataGridView datagridview)
        {
            try
            {
                VirusTotalNET.VirusTotal virusTotal = new VirusTotalNET.VirusTotal(APIKey);

                //Use HTTPS instead of HTTP
                virusTotal.UseTLS = true;

                ////Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html

                //////test
                //FileInfo fileInfo = new FileInfo("EICAR.txt");
                //File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

                FileInfo fileInfo = new FileInfo(path);

                //Check if the file has been scanned before.
                FileReport fileReport = await virusTotal.GetFileReport(fileInfo);
                bool hasFileBeenScannedBefore = fileReport.ResponseCode == ReportResponseCode.Present;

                //If the file has been scanned before, the results are embedded inside the report.
                if (hasFileBeenScannedBefore)
                {
                    PrintScan(fileReport, path, hasFileBeenScannedBefore, richtextbox, datagridview);
                }
                else
                {
                    ScanResult fileResult = await virusTotal.ScanFile(fileInfo);
                    PrintScan(fileResult, path, hasFileBeenScannedBefore, richtextbox, datagridview);
                }
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "Something went wrong!");
            }
        }

        private static void PrintScan(UrlScanResult scanResult, string name, bool hasUrlBeenScannedBefore, RichTextBox richtextbox, DataGridView datagridview)
        {
            richtextbox.Text = "Scanned URL: " + name + "\n\nURL has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes\n" : "No\n\nNote: Scanning may take some time, please try to scan again in a while to see the result!"); //removed part  + "Scan ID: " + scanResult.ScanId + "\n" + "Message: " + scanResult.VerboseMsg
            richtextbox.ForeColor = Color.DarkBlue;
        }

        private static void PrintScan(ScanResult scanResult, string name, bool hasUrlBeenScannedBefore, RichTextBox richtextbox, DataGridView datagridview)
        {
            richtextbox.Text = "Scanned File: " + name + "\n\nFile has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes\n" : "No\n\nNote: Scanning may take some time,  please try to scan again in a while to see the result!"); //removed part  + "Scan ID: " + scanResult.ScanId + "\n" + "Message: " + scanResult.VerboseMsg
            richtextbox.ForeColor = Color.DarkBlue;
        }

        private static void PrintScan(FileReport fileReport, string name, bool hasUrlBeenScannedBefore, RichTextBox richtextbox, DataGridView datagridview)
        {
            int infectednum = 0, cleannum = 0, count = 0;
            string result = "Scanned File: " + name + "\n\nFile has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes\n" : "No\n\nNote: Scanning may take some time, please try to scan again in a while to see the result!"); //removed part + "Scan ID: " + fileReport.ScanId + "\n" + "Message: " + fileReport.VerboseMsg
            richtextbox.Text = result;

            if (fileReport.ResponseCode == ReportResponseCode.Present)
            {
                
                foreach (KeyValuePair<string, ScanEngine> scan in fileReport.Scans)
                {
                    datagridview.Rows.Add();
                    datagridview.Rows[count].HeaderCell.Value = count.ToString();
                    datagridview.Rows[count].Cells[0].Value = scan.Key;
                    datagridview.Rows[count].Cells[1].Value = (scan.Value.Detected ? "Infected" : "Clean");
                    datagridview.Rows[count].Cells[2].Value = scan.Value.Result;

                    if (scan.Value.Detected)
                    {
                        datagridview.Rows[count].DefaultCellStyle.BackColor = Color.Red;
                        infectednum++;
                    }
                    else
                    {
                        datagridview.Rows[count].DefaultCellStyle.BackColor = Color.Green;
                        cleannum++;
                    }

                    count++;
                }
                datagridview.ClearSelection();

                if (infectednum == 0)
                    richtextbox.ForeColor = Color.Green;
                else
                    richtextbox.ForeColor = Color.Red;

            }

            richtextbox.Text += "\nDetection ratio: " + infectednum + "/" + count;

        }

        private static void PrintScan(UrlReport urlReport, string name, bool hasUrlBeenScannedBefore, RichTextBox richtextbox, DataGridView datagridview)
        {
            int infectednum = 0, cleannum = 0, count = 0; ;
            string result = "Scanned URL: " + name + "\n\nURL has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes\n" : "No\n\nNote: Scanning may take some time, please try to scan again in a while to see the result!"); //removed part  + "Scan ID: " + urlReport.ScanId + "\n" + "Message: " + urlReport.VerboseMsg
            richtextbox.Text = result;

            if (urlReport.ResponseCode == ReportResponseCode.Present)
            {
                foreach (KeyValuePair<string, ScanEngine> scan in urlReport.Scans)
                {
                    datagridview.Rows.Add();
                    datagridview.Rows[count].HeaderCell.Value = count.ToString();
                    datagridview.Rows[count].Cells[0].Value = scan.Key;
                    datagridview.Rows[count].Cells[1].Value = (scan.Value.Detected ? "Infected" : "Clean");
                    datagridview.Rows[count].Cells[2].Value = scan.Value.Result;

                    if (scan.Value.Detected)
                    {
                        datagridview.Rows[count].DefaultCellStyle.BackColor = Color.Red;
                        infectednum++;
                    }
                    else
                    {
                        datagridview.Rows[count].DefaultCellStyle.BackColor = Color.Green;
                        cleannum++;
                    }

                    count++;
                }

                datagridview.ClearSelection();
                if (infectednum == 0)
                    richtextbox.ForeColor = Color.Green;
                else
                    richtextbox.ForeColor = Color.Red;

            }

            richtextbox.Text += "\nDetection ratio: " + infectednum + "/" + count;


        }




    }
}
