package report

import (
	"bytes"
	"fmt"
	"html"
	"strings"
)

// ExportHTML outputs a styled, single-file HTML report.
func ExportHTML(r *RepositoryRiskReport) (string, error) {
	var buf bytes.Buffer

	overall := "ALLOW"
	overallClass := "status-allow"
	if r.Summary.Blocked > 0 {
		overall = "BLOCK"
		overallClass = "status-block"
	} else if r.Summary.Warnings > 0 {
		overall = "WARN"
		overallClass = "status-warn"
	}

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PkgSafe Repository Risk Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: #1e293b;
            margin: 0;
            padding: 40px 20px;
            line-height: 1.5;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
        }
        header {
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 {
            color: #0f172a;
            margin: 0 0 8px 0;
            font-size: 28px;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }
        .meta-item {
            background: #f1f5f9;
            padding: 16px;
            border-radius: 8px;
        }
        .meta-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #64748b;
            margin-bottom: 4px;
        }
        .meta-val {
            font-weight: 600;
            color: #334155;
        }
        .status-badge {
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 16px;
            display: inline-block;
        }
        .status-allow { background-color: #dcfce7; color: #15803d; }
        .status-warn { background-color: #fef9c3; color: #a16207; }
        .status-block { background-color: #fee2e2; color: #b91c1c; }

        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }
        .card {
            border: 1px solid #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            background: #fff;
            text-align: center;
        }
        .card-val {
            font-size: 32px;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 4px;
        }
        .card-label {
            font-size: 14px;
            color: #64748b;
        }

        h2 {
            font-size: 20px;
            color: #0f172a;
            margin-top: 40px;
            margin-bottom: 16px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
        }
        th, td {
            text-align: left;
            padding: 12px 16px;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background-color: #f8fafc;
            color: #475569;
            font-weight: 600;
        }
        tr:hover {
            background-color: #f8fafc;
        }
        ul {
            padding-left: 20px;
        }
        li {
            margin-bottom: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>PkgSafe Risk Report</h1>
                <div>Generated on ` + r.GeneratedAt + `</div>
            </div>
            <div class="status-badge ` + overallClass + `">` + overall + `</div>
        </header>

        <div class="meta-grid">
            <div class="meta-item">
                <div class="meta-label">Repository</div>
                <div class="meta-val">` + html.EscapeString(r.Repository.Name) + `</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Policy Pack</div>
                <div class="meta-val">` + html.EscapeString(r.Policy.PackName) + `@` + html.EscapeString(r.Policy.PackVersion) + `</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Source</div>
                <div class="meta-val">` + html.EscapeString(r.Policy.Source) + `</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">PkgSafe Version</div>
                <div class="meta-val">0.9.0</div>
            </div>
        </div>

        <h2>Executive Summary</h2>
        <div class="cards-grid">
            <div class="card">
                <div class="card-val">` + fmt.Sprintf("%d", r.Summary.PackagesScanned) + `</div>
                <div class="card-label">Packages Scanned</div>
            </div>
            <div class="card">
                <div class="card-val">` + fmt.Sprintf("%d", r.Summary.Blocked) + `</div>
                <div class="card-label">Blocked Packages</div>
            </div>
            <div class="card">
                <div class="card-val">` + fmt.Sprintf("%d", r.Summary.Warnings) + `</div>
                <div class="card-label">Warnings</div>
            </div>
            <div class="card">
                <div class="card-val">` + fmt.Sprintf("%d", r.Summary.CriticalVulnerabilities+r.Summary.HighVulnerabilities) + `</div>
                <div class="card-label">High/Critical CVEs</div>
            </div>
        </div>

        <h2>Findings Table</h2>
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Ecosystem</th>
                    <th>Version</th>
                    <th>Decision</th>
                    <th>Risk Score</th>
                    <th>Top Reason</th>
                </tr>
            </thead>
            <tbody>`)

	if len(r.Findings) == 0 {
		buf.WriteString("<tr><td colspan=\"6\">No packages detected or scanned.</td></tr>")
	} else {
		for _, f := range r.Findings {
			decClass := "status-badge status-allow"
			if f.Decision == "block" {
				decClass = "status-badge status-block"
			} else if f.Decision == "warn" {
				decClass = "status-badge status-warn"
			}

			fmt.Fprintf(&buf, `<tr>
                <td><strong>%s</strong></td>
                <td>%s</td>
                <td>%s</td>
                <td><span class="%s">%s</span></td>
                <td>%d</td>
                <td>%s</td>
            </tr>`, html.EscapeString(f.Package), html.EscapeString(f.Ecosystem), html.EscapeString(nonEmpty(f.Version, "*")), decClass, strings.ToUpper(f.Decision), f.RiskScore, html.EscapeString(f.Message))
		}
	}

	buf.WriteString(`</tbody>
        </table>

        <h2>Active Exceptions</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Package</th>
                    <th>Ecosystem</th>
                    <th>Reason</th>
                    <th>Expiry</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>`)

	activeExcCount := 0
	for _, exc := range r.Exceptions {
		if exc.Status == "Active" {
			activeExcCount++
			fmt.Fprintf(&buf, `<tr>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td><span class="status-badge status-allow">Active</span></td>
            </tr>`, html.EscapeString(exc.ID), html.EscapeString(exc.Package), html.EscapeString(exc.Ecosystem), html.EscapeString(exc.Reason), exc.AllowedUntil.Format("2006-01-02"))
		}
	}
	if activeExcCount == 0 {
		buf.WriteString("<tr><td colspan=\"6\">No active exceptions.</td></tr>")
	}

	buf.WriteString(`</tbody>
        </table>

        <h2>Private Registry Evidence</h2>
        <table>
            <thead>
                <tr>
                    <th>Registry Name</th>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Resolution Count</th>
                    <th>Mismatch Blocks</th>
                </tr>
            </thead>
            <tbody>`)

	if len(r.Registries) == 0 {
		buf.WriteString("<tr><td colspan=\"5\">No registry policies configured.</td></tr>")
	} else {
		for _, reg := range r.Registries {
			fmt.Fprintf(&buf, `<tr>
                <td>%s</td>
                <td>%s</td>
                <td><code>%s</code></td>
                <td>%d</td>
                <td>%d</td>
            </tr>`, html.EscapeString(reg.Name), html.EscapeString(reg.Type), html.EscapeString(reg.URL), reg.ResolutionCount, reg.MismatchBlocks)
		}
	}

	buf.WriteString(`</tbody>
        </table>

        <h2>Remediation Recommendations</h2>
        <ul>`)

	if len(r.Recommendations) == 0 {
		buf.WriteString("<li>No remediation required.</li>")
	} else {
		for _, rec := range r.Recommendations {
			fmt.Fprintf(&buf, "<li>%s</li>", html.EscapeString(rec.Message))
		}
	}

	buf.WriteString(`</ul>
    </div>
</body>
</html>
`)

	return buf.String(), nil
}
