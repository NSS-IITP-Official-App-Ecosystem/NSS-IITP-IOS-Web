// pdf_export.js
// Handles the PDF generation for the NSS Web App.

export function generatePDFReport(profileData, currentEventsSemester, { showLoader, showToast }) {
    if (!profileData) {
        showToast("error", "Error", "Profile data not loaded yet.");
        return;
    }
    
    showLoader(true, "Generating PDF...");
    setTimeout(() => {
        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            // Date formatter to match Android "18 Apr 2026"
            const formatDate = (dateString) => {
                if (!dateString) return '';
                const parts = dateString.split(/[-/]/);
                let dateObj;
                if (parts.length >= 3) {
                    dateObj = parts[0].length === 4 ? new Date(parts[0], parts[1]-1, parts[2]) : new Date(parts[2], parts[1]-1, parts[0]);
                } else {
                    dateObj = new Date(dateString);
                }
                if (isNaN(dateObj.getTime())) return dateString;
                
                const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                const day = String(dateObj.getDate()).padStart(2, '0');
                const month = months[dateObj.getMonth()];
                const year = dateObj.getFullYear();
                return `${day} ${month}\n${year}`;
            };
            
            // Filter events for the current semester
            const parseDate = (d) => {
                if (!d) return 0;
                const parts = d.split(/[-/]/);
                if (parts.length >= 3) return parts[0].length === 4 ? new Date(parts[0], parts[1]-1, parts[2]).getTime() : new Date(parts[2], parts[1]-1, parts[0]).getTime();
                const parsed = new Date(d).getTime();
                return isNaN(parsed) ? 0 : parsed;
            };
            const sortFn = (a, b) => parseDate(b.date) - parseDate(a.date);
            const wingEvs = (profileData.wingEvents || []).filter(e => e.semester === currentEventsSemester).sort(sortFn);
            const openEvs = (profileData.openEvents || []).filter(e => e.semester === currentEventsSemester).sort(sortFn);
            
            const wingHours = wingEvs.reduce((s, e) => s + (Number(e.hours) || 0), 0);
            const openHours = openEvs.reduce((s, e) => s + (Number(e.hours) || 0), 0);
            const totalHours = wingHours + openHours;
            const totalEvents = wingEvs.length + openEvs.length;
            
            // Title
            doc.setFontSize(18);
            doc.setFont("helvetica", "bold");
            doc.text(`Semester ${currentEventsSemester} Events Summary`, 105, 20, { align: 'center' });
            
            // Summary Table
            doc.autoTable({
                startY: 30,
                theme: 'grid',
                body: [
                    [{ content: 'Name:', styles: { fontStyle: 'bold' } }, profileData.name || "Student"],
                    [{ content: 'Roll Number:', styles: { fontStyle: 'bold' } }, profileData.rollNumber],
                    [{ content: 'Semester:', styles: { fontStyle: 'bold' } }, currentEventsSemester.toString()],
                    [{ content: 'Total Hours:', styles: { fontStyle: 'bold' } }, totalHours.toString()],
                    [{ content: 'Events Attended:', styles: { fontStyle: 'bold' } }, totalEvents.toString()]
                ],
                columnStyles: {
                    0: { cellWidth: 50, fillColor: [230, 242, 255] } // DeviceRgb(0.9f, 0.95f, 1.0f)
                },
                styles: { textColor: [0, 0, 0], lineColor: [0, 0, 0], lineWidth: 0.1, fontSize: 11, cellPadding: 3 }
            });
            
            let finalY = doc.lastAutoTable.finalY + 15;
            
            // Wing Events
            doc.setFontSize(14);
            doc.setFont("helvetica", "bold");
            doc.text(`Wing Events Hours = ${wingHours}`, 15, finalY);
            
            if (wingEvs.length > 0) {
                const wingTableBody = wingEvs.map(e => [
                    e.eventName, formatDate(e.date), (e.wings || []).join(", "), e.hours
                ]);
                doc.autoTable({
                    startY: finalY + 5,
                    head: [['Event', 'Date', 'Wing', 'Hours']],
                    body: wingTableBody,
                    theme: 'grid',
                    headStyles: { fillColor: [51, 102, 153], textColor: [255, 255, 255], fontStyle: 'bold', halign: 'center' },
                    styles: { textColor: [0, 0, 0], lineColor: [0, 0, 0], lineWidth: 0.1, fontSize: 10, cellPadding: 3, valign: 'middle' },
                    columnStyles: {
                        0: { cellWidth: 55 },
                        1: { cellWidth: 15, halign: 'center' },
                        2: { cellWidth: 'auto' },
                        3: { cellWidth: 12, halign: 'center' }
                    },
                    margin: { left: 15, right: 15 }
                });
                finalY = doc.lastAutoTable.finalY + 15;
            } else {
                finalY += 10;
            }
            
            // Open Events
            doc.setFontSize(14);
            doc.setFont("helvetica", "bold");
            doc.text(`Open Event Hours = ${openHours}`, 15, finalY);
            
            if (openEvs.length > 0) {
                const openTableBody = openEvs.map(e => [
                    e.eventName, formatDate(e.date), (e.wings || []).join(", "), e.hours
                ]);
                doc.autoTable({
                    startY: finalY + 5,
                    head: [['Event', 'Date', 'Wing', 'Hours']],
                    body: openTableBody,
                    theme: 'grid',
                    headStyles: { fillColor: [51, 102, 153], textColor: [255, 255, 255], fontStyle: 'bold', halign: 'center' },
                    styles: { textColor: [0, 0, 0], lineColor: [0, 0, 0], lineWidth: 0.1, fontSize: 10, cellPadding: 3, valign: 'middle' },
                    columnStyles: {
                        0: { cellWidth: 55 },
                        1: { cellWidth: 15, halign: 'center' },
                        2: { cellWidth: 'auto' },
                        3: { cellWidth: 12, halign: 'center' }
                    },
                    margin: { left: 15, right: 15 }
                });
            }
            
            // Timestamp format: 20260801_155424
            const now = new Date();
            const yyyy = now.getFullYear();
            const mm = String(now.getMonth() + 1).padStart(2, '0');
            const dd = String(now.getDate()).padStart(2, '0');
            const hh = String(now.getHours()).padStart(2, '0');
            const min = String(now.getMinutes()).padStart(2, '0');
            const ss = String(now.getSeconds()).padStart(2, '0');
            const timestamp = `${yyyy}${mm}${dd}_${hh}${min}${ss}`;
            
            doc.save(`NSS_S${currentEventsSemester}_${profileData.rollNumber}_Events_${timestamp}.pdf`);
            showLoader(false);
            showToast("success", "Success", "PDF Report downloaded successfully.");
            
        } catch (err) {
            console.error("PDF Generation Error:", err);
            showLoader(false);
            showToast("error", "Error", "Failed to generate PDF. See console.");
        }
    }, 100);
}
