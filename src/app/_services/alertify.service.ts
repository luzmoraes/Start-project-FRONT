import { Injectable } from '@angular/core';
import alertify from 'alertifyjs';

@Injectable({
  providedIn: 'root'
})
export class AlertifyService {

  constructor() {
    alertify.defaults = {
      // dialogs defaults
      autoReset:true,
      basic:false,
      closable:true,
      closableByDimmer:true,
      frameless:false,
      maintainFocus:true, // <== global default not per instance, applies to all dialogs
      maximizable:true,
      modal:true,
      movable:true,
      moveBounded:false,
      overflow:true,
      padding: true,
      pinnable:true,
      pinned:true,
      preventBodyShift:false, // <== global default not per instance, applies to all dialogs
      resizable:true,
      startMaximized:false,
      transition:'pulse',

      // notifier defaults
      notifier:{
          // auto-dismiss wait time (in seconds)  
          delay:5,
          // default position
          position:'bottom-right',
          // adds a close button to notifier messages
          closeButton: false
      },

      // language resources 
      glossary:{
          // dialogs default title
          title:'AlertifyJS',
          // ok button text
          ok: 'Ok',
          // cancel button text
          cancel: 'Cancelar'            
      },

      // theme settings
      theme:{
          // class name attached to prompt dialog input textbox.
          // input:'ajs-input',
          // class name attached to ok button
          // ok:'ajs-ok',
          // class name attached to cancel button 
          // cancel:'ajs-cancel'
          
          ok: "btn btn-info",
          cancel: "btn btn-danger",
          input: "form-control"
      }
    };
  }

  confirm(title: string, message: string, onok: () => any, oncancel: () => any) {
    alertify.defaults.glossary.ok = 'Sim';
    alertify.defaults.glossary.cancel = 'Não';
    alertify.confirm(`<h4>${title}</h4>`, message, onok, oncancel);
  }

  success(message: string) {
    alertify.success(message);
  }

  error(message: string) {
    alertify.error(message);
  }

  warning(message: string) {
    alertify.warning(message);
  }

  message(message: string) {
    alertify.message(message);
  }

  alert(title: string, message: string, onok: () => any) {
    alertify.alert(`<h4>${title}</h4>`, message, onok);
  }
  
}
