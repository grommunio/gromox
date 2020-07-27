var HG = {
	Version: '2.0',
	Author: 'Young.Jiang',
	Email:'holygrace.cn@gmail.com',
	WebSite:"http://www.holygrace.cn"
};

(function($) {
    $.fn.calendar=function(options){
        options = $.extend({ 
            initDate:new Date(),
            monthText:["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"],
            weekText:["su","mo","tu","we","th","fr","sa"],
            yearText:[""],
            todayText:["today"],
            range:[new Date(2000,0,1),new Date(2050,0,1)],
            clickEvent:null
        },options);
        function MonthInfo(y,m){
            var monthDays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];                
            var d = (new Date(y,m,1));
            d.setDate(1);
            if (d.getDate() == 2) d.setDate(0);
            y +=1900;
            return {
                days : m==1?(((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0)?29:28):monthDays[m],
                firstDay : d.getDay()
            };
        };
        function InitCalendar(cal,date){
            cal.html("");
            var month=MonthInfo(date.getFullYear(),date.getMonth());
            cal.addClass("calendar");
            var year=$("<ul><li class='calendar_logo'></li></ul>");
            year.append("<li class='calendar_year'><a href='#' cal='year' year='"+date.getFullYear()+"'>"+date.getFullYear()+options.yearText[0]+"</a></li>").append("<li class='calendar_month' month='"+date.getMonth()+"'><a href='#' cal='month'>"+options.monthText[date.getMonth()]+"</a></li>");
            cal.append(year);
            
            var today=$("<ul></ul>");
            today.append("<li><a href='#' cal='preyear'><<</a></li>").append("<li><a href='#' cal='preweek'><</a></li>").append("<li class='calendar_today'><a href='#' cal='today'>"+options.todayText[0]+"</a></li>").append("<li><a href='#' cal='nextweek'>></a></li>").append("<li><a href='#' cal='nextyear'>>></a></li>");
            cal.append(today);
            
            var week=$("<ul></ul>");
            for(i=0;i<7;i++){
                week.append("<li class='calendar_week'>"+options.weekText[i]+"</li>")
            };            
            cal.append(week);
            for(i=0;i<6;i++){
                var days=$("<ul></ul>");
                for(var j=0;j<7;j++){
                    var d=7*i -month.firstDay + j + 1;
                    var css=d==date.getDate()?"class='calendar_selected'":"";
                    if(d>0 && d<=month.days){
                        var curd=new Date(date.getFullYear(),date.getMonth(),d);
                        if(curd>=options.range[0] && curd<=options.range[1]) {             
                            days.append("<li><a href='#' "+css+" year='"+date.getFullYear()+"' month='"+date.getMonth()+"' date='"+d+"'>"+d+"</a></li>");
                        }else{
                            days.append("<li class='calendar_outrange'>"+d+"</li>");}
                    }else{
                        days.append("<li class='calendar_invalid'>&nbsp;</li>")
                    }
                };
                cal.append(days);
            };
            cal.find("a").focus(function(){this.blur()});
            cal.find("a").click(function(){
                if($(this).attr("cal")=="today"){
                    InitCalendar(cal,new Date());
                    if(options.clickEvent!=null)                        
                        options.clickEvent(new Date());
                }
                else if($(this).attr("cal")=="preyear"){
                    date.setFullYear(date.getFullYear()-1);
                    InitCalendar(cal,date);
                }
                else if($(this).attr("cal")=="nextyear"){
                    date.setFullYear(date.getFullYear()+1);
                    InitCalendar(cal,date);
                }
                else if($(this).attr("cal")=="preweek"){
                    date.setMonth(date.getMonth()-1);
                    InitCalendar(cal,date);
                }
                else if($(this).attr("cal")=="nextweek"){
                    date.setMonth(date.getMonth()+1);
                    InitCalendar(cal,date);
                }
                else if($(this).attr("cal")=="year"){
                    var year=$("<select style='width:"+(this.clientWidth-4)+"px'></select>");
                    var selected=$(this).attr('year');
                    for(var i=options.range[0].getFullYear();i<=options.range[1].getFullYear();i++){
                        year.append("<option value='"+i+"'>"+i+"</option>");
                    };
                    year.change(function(){                    
                        date.setFullYear(this.value);
                        InitCalendar(cal,date);                    
                    });
                    year.val(selected);
                    $(this).replaceWith(year);
                    
                }
                else if($(this).attr("cal")=="month"){
                    var mon=$("<select style='width:"+(this.clientWidth-4)+"px'></select>");
                    selected=$(this).attr('month');
                    for(i=0;i<12;i++){
                        mon.append("<option value='"+i+"'>"+options.monthText[i]+"</option>");
                    };
                    mon.change(function(){                    
                        date.setMonth(this.value);
                        InitCalendar(cal,date);                    
                    });
                    mon.val(selected);
                    $(this).replaceWith(mon);                    
                }
                else{
                    cal.find(".calendar_selected").removeAttr("class");                
                    this.className="calendar_selected";
                    if(options.clickEvent!=null)
                         options.clickEvent(new Date($(this).attr("year"),$(this).attr("month"),$(this).attr("date")));
                };               
                return false;
            })
        };
        return this.each(function() {
            var cal=$(this);               
            var date=options.initDate;
            InitCalendar(cal,date);            
        })
    }
})(jQuery);


(function($){
     $.fn.datepicker=function(options){
        options = $.extend({ 
            initDate:"",
            monthText:["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"],
            weekText:["su","mo","tu","we","th","fr","sa"],
            yearText:[""],
            todayText:["today"],
            range:[new Date(2000,0,1),new Date(2050,0,1)],            
            splitChar:"-"
        },options);
        return this.each(function() {
             $(this).click(function(){
                if($("#"+this.id+"_date").length==0){
                    var area=$("<div id='"+this.id+"_date'></div>");
                    var dateinput=this;
                    var initdate=new Date();
                    if(this.value!=""){
                        var d=  dateinput.value.split(options.splitChar);
                        initdate=new Date(d[0],d[1]-1,d[2]);
                    };
                    area.calendar({
                        initDate:initdate,
                        range:options.range,
                        monthText:options.monthText,
                        weekText:options.weekText,
                        yearText:options.yearText,
                        todayText:options.todayText,
                        clickEvent:function(date){
                            dateinput.value=date.getFullYear()+options.splitChar+(date.getMonth()+1)+options.splitChar+date.getDate();
                            area.remove();
                        }
                    });
                    var offset=$(this).offset();
                    area.css({
                        position:"absolute",
                        left:$(this).offset().left,
                        top:$(this).offset().top+this.clientHeight
                    });
                    $("body").append(area);
                }else{
                    $("#"+this.id+"_date").remove();
                }
            });
        })
    }
})(jQuery);
