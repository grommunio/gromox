/*--------------------------------------------------|
| Phenix PanelBar | www.seu.edu.cn                  |
|---------------------------------------------------|
|                                                   |
|  I believe one day I can fly like phenix!         |
|                                                   |
| Finished: 17.11.2004                              |
|--------------------------------------------------*/

//item object
//alert("arrived here");
function PhenItem(id,pid,label,url,type,img,over,img2,over2,title,target){
	
   this.id=id;
   this.pid=pid;
   this.label=label;
   this.url=url;
   this.title=title;
   this.target=target;
   this.img=img;
   this.over=over;
   this.img2=img2;
   this.over2=over2;
   this.type=type;
   //this._ih = false;	//is it the head item?
   this._hc = false;   //has the child item?
   this._ls = false;	//has sibling item?
   this._io = false;	//whether the panelbar is open?
};


//menu object
function PhenMenu(objName) {

    this.config = {

		closeSameLevel	: true

	};
	//alert("asdsdf");
	this.obj = objName;

	this.items = [];
	
	this.root = new PhenItem(-1);
		
};

//add a new item to the item array
PhenMenu.prototype.add = function(id,pid,label,url,type,img,over,img2,over2,title,target){
	this.items[this.items.length] = new PhenItem(id,pid,label,url,type,img,over,img2,over2,title,target);
};

// Outputs the menu to the page
PhenMenu.prototype.toString = function() {
	//alert("arrived here");
	var str = '<div>\n';

	if (document.getElementById) {

		str += this.addItem(this.root);

	} else str += 'Browser not supported.';

	str += '\n</div>';
    //alert(str);
	//document.write(str);
	//alert(this.items[0]._hc);
	return str;

};

// Creates the menu structure
PhenMenu.prototype.addItem = function(pItem) {

	var str = '';

	//var n=0;

	for (var n=0; n<this.items.length; n++) {
		
		if(this.items[n].pid == pItem.id){
			
			var ci = this.items[n];
			//alert(ci.pid);
			//alert(ci.id);
			this.setHS(ci);
			//alert("item:"+ci._hc);
			//alert(ci._ls);
			str += this.itemCreate(ci, n);
			
			if(ci._ls) break;
			
		}

	}

	return str;

};

// Creates the node icon, url and text
PhenMenu.prototype.itemCreate = function(pItem, itemId) {
//alert(pItem.type.toLowerCase());
	var str = '';
	
    if (pItem.type == 'header') {
		if (pItem.url) {
			str = '<table width="100%" class="header" valign="middle" onmouseover="this.className=\'headerSelected\'" onmouseout="this.className=\'header\'" onclick="parent.location.href=\'' + pItem.url + '\'"><tr><td>';
		} else {
			str = '<table width="100%" class="header" valign="middle" onmouseover="this.className=\'headerSelected\'" onmouseout="this.className=\'header\'" onclick="'+this.obj+'.o('+itemId+')"><tr><td>';
		}
	} else {
		str = '<table width="100%" class="item" valign="middle" onmouseover="this.className=\'itemOver\'" onmouseout="this.className=\'item\'" onclick="'+this.obj+'.o('+itemId+')"><tr><td>';
	}
	if (pItem.img) {

		str += '&nbsp;&nbsp;<img id="i' + this.obj + itemId + '" src="' + pItem.img + '" alt="" />';

	}
	if (pItem.url) {
		if (pItem.type == 'header') {
			str += '<a id="s' + this.obj + itemId + '" class="navigation_header" href="' + pItem.url + '"';
			if (pItem.title) str += ' title="' + pItem.title + '"';
			if (pItem.target) str += ' target="' + pItem.target + '"';
			str += ' onmouseover="window.status=\'' + pItem.label + '\';return true;" onmouseout="window.status=\'\';return true;"';
			str += '>';
		} else {
			str += '<a id="s' + this.obj + itemId + '" class="navigation_item" href="' + pItem.url + '"';
			if (pItem.title) str += ' title="' + pItem.title + '"';
			if (pItem.target) str += ' target="' + pItem.target + '"';
			str += ' onmouseover="window.status=\'' + pItem.label + '\';return true;" onmouseout="window.status=\'\';return true;"';
			str += '>';
		}
	}
	str += '&nbsp;&nbsp;&nbsp;&nbsp;' + pItem.label;
	if (pItem.url) str += '</a>';
	str += '</td></tr></table>';
	//alert(pItem.url);
	//alert(str);
	if (pItem._hc) {
		str += '<table id="ct' + this.obj + itemId + '" width="100%" style="display:' + ((pItem._io) ? 'block' : 'none') + '; VISIBILITY: hidden"><tr><td>';
		str += this.addItem(pItem);
		str += '</td></tr></table>';
		//alert(str);
		//document.write(str);
	}

	return str;
};


// Checks whether a item has child and if it is the last sibling
PhenMenu.prototype.setHS = function(pItem) {

	var lastId;

	for (var n=0; n<this.items.length; n++) {

		if (this.items[n].pid == pItem.id) pItem._hc = true;

		if (this.items[n].pid == pItem.pid) lastId = this.items[n].id;

	}

	if (lastId==pItem.id) pItem._ls = true;

};

// Toggle Open or close
PhenMenu.prototype.o = function(id) {
	//alert(this.items.length);
	var ci = this.items[id];
    //alert(ci);
	//this.setHS(ci);
	//alert(this.items[id]._hc);
	this.itemStatus(!ci._io, id);

	ci._io = !ci._io;
    
	if (this.config.closeSameLevel) this.closeLevel(ci);

};

// Change the status of a item(open or closed)
PhenMenu.prototype.itemStatus = function(status, id) {

	cTable	= document.getElementById('ct' + this.obj + id);

	if (cTable == null) {
		return;
	}

	if(status){
		cTable.style.display = 'block';
		cTable.style.visibility = "";
	} else {
		cTable.style.display = 'none';
	}
	//cDiv.style.display = (status) ? 'block': 'none';

};

// Closes all items on the same level as certain item
PhenMenu.prototype.closeLevel = function(pItem) {
               //alert(this.items[0]._hc);
	for (var n=0; n<this.items.length; n++) {
            //alert(this.items[n]._hc);
		if ((this.items[n].pid == pItem.pid) && (this.items[n].id != pItem.id) && this.items[n]._hc) {
			
			this.itemStatus(false, n);

			this.items[n]._io = false;

			this.closeAllChildren(this.items[n]);

		}

	}

};

PhenMenu.prototype.closeAllChildren = function(pItem) {

	for (var n=0; n<this.items.length; n++) {

		if (this.items[n].pid == pItem.id && this.items[n]._hc) {

			if (this.items[n]._io) this.itemStatus(false, n);

			this.items[n]._io = false;

			this.closeAllChildren(this.items[n]);		

		}

	}

};
