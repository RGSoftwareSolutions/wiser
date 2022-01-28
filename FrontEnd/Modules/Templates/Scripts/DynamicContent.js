﻿import { TrackJS } from "trackjs";
import { Modules, Dates, Strings, Wiser2, Misc } from "../../Base/Scripts/Utils.js";
import "../../Base/Scripts/Processing.js";

require("@progress/kendo-ui/js/kendo.notification.js");
require("@progress/kendo-ui/js/kendo.button.js");
require("@progress/kendo-ui/js/kendo.combobox.js");
require("@progress/kendo-ui/js/kendo.editor.js");
require("@progress/kendo-ui/js/kendo.splitter.js");
require("@progress/kendo-ui/js/kendo.tabstrip.js");
require("@progress/kendo-ui/js/kendo.treeview.js");
require("@progress/kendo-ui/js/kendo.grid.js");
require("@progress/kendo-ui/js/kendo.datetimepicker.js");
require("@progress/kendo-ui/js/kendo.multiselect.js");
require("@progress/kendo-ui/js/cultures/kendo.culture.nl-NL.js");
require("@progress/kendo-ui/js/messages/kendo.messages.nl-NL.js");

import "../css/DynamicContent.css";

// Any custom settings can be added here. They will overwrite most default settings inside the module.
const moduleSettings = {

};

((settings) => {
    /**
     * Main class.
     */
    class DynamicContent {

        /**
         * Initializes a new instance of DynamicContent.
         * @param {any} settings An object containing the settings for this class.
         */
        constructor(settings) {
            this.base = this;

            // Kendo components.
            this.mainSplitter = null;
            this.mainTabStrip = null;
            this.mainWindow = null;
            this.componentTypeComboBox = null;
            this.componentModeComboBox = null;
            this.mainComboInput = null;
            this.mainMultiSelect = null;
            this.mainNumericTextBox = null;
            this.mainDatePicker = null;
            this.mainDateTimePicker = null;
            this.selectedComponentData = null;

            // Default settings
            this.settings = {
                moduleId: 0,
                customerId: 0,
                username: "Onbekend",
                userEmailAddress: "",
                userType: ""
            };
            Object.assign(this.settings, settings);

            // Other.
            this.mainLoader = null;

            // Set the Kendo culture to Dutch. TODO: Base this on the language in Wiser.
            kendo.culture("nl-NL");

            // Add logged in user access token to default authorization headers for all jQuery ajax requests.
            $.ajaxSetup({
                headers: { "Authorization": `Bearer ${localStorage.getItem("accessToken")}` }
            });

            // Fire event on page ready for direct actions
            $(document).ready(() => {
                this.onPageReady();
            });
        }

        /**
         * Event that will be fired when the page is ready.
         */
        async onPageReady() {
            this.mainLoader = $("#mainLoader");

            // Setup processing.
            document.addEventListener("processing.Busy", this.toggleMainLoader.bind(this, true));
            document.addEventListener("processing.Idle", this.toggleMainLoader.bind(this, false));

            const process = `initialize_${Date.now()}`;
            window.processing.addProcess(process);

            // Fullscreen event for elements that can go fullscreen, such as HTML editors.
            const classHolder = $(document.documentElement);
            const fullscreenChange = "webkitfullscreenchange mozfullscreenchange fullscreenchange MSFullscreenChange";
            $(document).bind(fullscreenChange, $.proxy(classHolder.toggleClass, classHolder, "k-fullscreen"));

            // Setup any settings from the body element data. These settings are added via the Wiser backend and they take preference.
            Object.assign(this.settings, $("body").data());

            if (this.settings.trackJsToken) {
                TrackJS.install({
                    token: this.settings.trackJsToken
                });
            }

            const user = JSON.parse(localStorage.getItem("userData"));
            this.settings.oldStyleUserId = user.oldStyleUserId;
            this.settings.username = user.adminAccountName ? `Happy Horizon (${user.adminAccountName})` : user.name;
            this.settings.adminAccountLoggedIn = !!user.adminAccountName;

            const userData = await Wiser2.getLoggedInUserData(this.settings.wiserApiRoot);
            this.settings.userId = userData.encryptedId;
            this.settings.customerId = userData.encryptedCustomerId;
            this.settings.zeroEncrypted = userData.zeroEncrypted;
            this.settings.filesRootId = userData.filesRootId;
            this.settings.imagesRootId = userData.imagesRootId;
            this.settings.templatesRootId = userData.templatesRootId;
            this.settings.mainDomain = userData.mainDomain;

            if (!this.settings.wiserApiRoot.endsWith("/")) {
                this.settings.wiserApiRoot += "/";
            }

            this.initializeKendoComponents();

            await this.initCurrentComponentData();

            this.bindSaveButton();
            await this.loadComponentHistory();
            window.processing.removeProcess(process);
        }

        async initCurrentComponentData() {
            this.selectedComponentData = await Wiser2.api({
                url: `${this.settings.wiserApiRoot}dynamic-content/${this.settings.selectedId}`,
                dataType: "json",
                method: "GET"
            });
            
            this.componentTypeComboBox.value(this.selectedComponentData.component);
            $("#visibleDescription").val(this.selectedComponentData.title);
            this.changeComponent(this.selectedComponentData.component, this.selectedComponentData.componentMode);
        }
        /**
         * Initializes all kendo components for the base class.
         */
        initializeKendoComponents() {
            window.popupNotification = $("#popupNotification").kendoNotification().data("kendoNotification");

            // Splitter
            this.mainSplitter = $("#horizontal").kendoSplitter({
                panes: [{
                    collapsible: true,
                    scrollable: false,
                    size: "75%"
                }, {
                    collapsible: true
                }]
            }).data("kendoSplitter");
            this.mainSplitter.resize(true);

            // Tabstrip, NUMERIC FIELD, MULTISELECT, Date Picker, DATE & TIME PICKER
            this.intializeDynamicKendoComponents();
            
            //Components
            this.componentTypeComboBox = $("#componentTypeDropDown").kendoComboBox({
                change: this.changeComponent.bind(this, document.getElementById("componentTypeDropDown").value)
            }).data("kendoComboBox");
        }

        //Initialize the dynamic kendo components. This method will also be called when reloading component fields.
        intializeDynamicKendoComponents() {
            // Tabstrip
            this.mainTabStrip = $(".tabstrip").kendoTabStrip({
                animation: {
                    open: {
                        effects: "fadeIn"
                    }
                }
            }).data("kendoTabStrip").select(0);

            //NUMERIC FIELD
            this.mainNumericTextBox = $(".numeric").kendoNumericTextBox();

            this.mainComboInput = $(".combo-input").kendoComboBox({
                dataTextField: "text",
                dataValueField: "value",
                dataSource: [{
                    text: "Netherlands",
                    value: "1"
                }, {
                    text: "Belgium",
                    value: "2"
                }, {
                    text: "Germany",
                    value: "3"
                }, {
                    text: "France",
                    value: "4"
                }, {
                    text: "Spain",
                    value: "5"
                }, {
                    text: "United Kingdom",
                    value: "6"
                }, {
                    text: "Italy",
                    value: "7"
                }, {
                    text: "Luxembourg",
                    value: "8"
                }],
                filter: "contains",
                suggest: true,
                index: 3
            });

            //MULTISELECT
            this.mainMultiSelect = $(".multi-select").kendoMultiSelect({
                autoClose: false
            }).data("kendoMultiSelect");

            //DATE PICKER
            if ($(".datepicker").length) {
                this.mainDatePicker = $(".datepicker").kendoDatePicker({
                    format: "dd MMMM yyyy",
                    culture: "nl-NL"
                }).data("kendoDatePicker");

                $(".datepicker").click(function () {
                    this.mainDatePicker.open();
                });
            }

            //DATE & TIME PICKER
            if ($(".datetimepicker").length) {
                this.mainDateTimePicker = $(".datetimepicker").kendoDateTimePicker({
                    value: new Date(),
                    dateInput: true,
                    format: "dd MMMM yyyy HH:mm",
                    culture: "nl-NL"
                }).data("kendoDateTimePicker");

                $("input.datetimepicker").click(function () {
                    this.mainDateTimePicker.close("time");
                    this.mainDateTimePicker.open("date");
                });

                this.mainDateTimePicker.dateView.options.change = function () {
                    this.mainDateTimePicker._change(this.value());
                    this.mainDateTimePicker.close("date");
                    this.mainDateTimePicker.open("time");
                };
            }
        }

        /**
         * Shows or hides the main (full screen) loader.
         * @param {boolean} show True to show the loader, false to hide it.
         */
        toggleMainLoader(show) {
            this.mainLoader.toggleClass("loading", show);
        }

        async changeComponent(newComponent, newComponentMode) {
            const process = `changeComponent_${Date.now()}`;
            window.processing.addProcess(process);

            try {
                const response = await Wiser2.api({
                    url: `/Modules/DynamicContent/${encodeURIComponent(newComponent)}/DynamicContentTabPane`,
                    method: "POST",
                    contentType: "application/json",
                    data: JSON.stringify(this.selectedComponentData)
                });

                //force reload on component modes
                this.componentModus = null;

                $("#DynamicContentTabPane").html(response);
                this.reloadComponentModes(newComponent, newComponentMode);
                this.intializeDynamicKendoComponents();
                await this.transformCodeMirrorViews();
            } catch (exception) {
                console.error(exception);
                kendo.alert("Er is iets fout gegaan. Probeer het a.u.b. opnieuw");
            }

            window.processing.removeProcess(process);
        }

        async reloadComponentModes(newComponent, newComponentMode) {
            const componentModes = await Wiser2.api({
                url: `${this.settings.wiserApiRoot}dynamic-content/${encodeURIComponent(newComponent)}/component-modes`,
                dataType: "json",
                method: "GET"
            });

            if (!this.componentModeComboBox) {
                this.componentModeComboBox = $("#componentMode").kendoComboBox({
                    change: this.updateComponentModeVisibility.bind(this),
                    dataTextField: "name",
                    dataValueField: "id"
                }).data("kendoComboBox");
            }

            this.componentModeComboBox.setDataSource(componentModes);
            this.componentModeComboBox.value(this.getComponentModeFromKey(newComponentMode));
            this.updateComponentModeVisibility(newComponentMode);
        }

        /**
         * On opening the dynamic content and switching between component modes this method will check which groups and properties should be visible. 
         * @param {number} componentModeKey The key value of the componentMode. This key will be used to retrieve the associated value.
         */
        updateComponentModeVisibility(componentModeKey) {
            let componentMode;
            if (typeof componentModeKey === "string") {
                componentMode = this.getComponentModeFromKey(componentModeKey);
            } else if (typeof componentModeKey === "number") {
                componentMode = componentModeKey;
            } else {
                componentMode = this.componentModeComboBox.value();
            }

            //Group visibility
            $(".item-group").hide();
            if (componentMode) {
                $(`.item-group:has(> [data-componentmode*='${componentMode}'])`).show();
                $(".item-group:has(> [data-componentmode=''])").show();
            }

            //Property visibility
            $("[data-componentmode]").hide();
            if (componentMode) {
                $(`[data-componentmode*="${componentMode}"]`).show();
                $("[data-componentmode='']").show();
            }
        }

        /**
         * Retrieves the associated value from the given component key.
         * @param {number} componentModeKey The key value for retrieving the componentMode.
         */
        getComponentModeFromKey(componentModeKey) {
            if (!componentModeKey) {
                console.warn("getComponentModeFromKey called with invalid componentModeKey", componentModeKey);
                return 0;
            }

            const result = this.componentModeComboBox.dataSource.data().filter(c => c.name === componentModeKey || c.id === parseInt(componentModeKey))[0];
            if (!result) {
                console.warn("getComponentModeFromKey called with invalid componentModeKey", componentModeKey);
                return 0;
            }

            return result.id;
        }

        /**
         *  Bind the save button to the event for saving the newly acquired settings.
         * */
        bindSaveButton() {
            document.getElementsByClassName("btn-primary")[0].addEventListener("click", (event) => {
                event.preventDefault();
                this.save();
            });

            document.getElementsByClassName("btn-secondary")[0].addEventListener("click", async (event) => {
                event.preventDefault();
                await this.save();
                window.parent.$("#DynamicContentWindow").data("kendoWindow").close();
            });
        }

        async save() {
            const process = `save_${Date.now()}`;
            window.processing.addProcess(process);

            try {
                await Wiser2.api({
                    url: `${this.settings.wiserApiRoot}dynamic-content/${this.settings.selectedId}`,
                    dataType: "json",
                    method: "POST",
                    contentType: "application/json",
                    data: JSON.stringify({
                        component: document.getElementById("componentTypeDropDown").value,
                        componentModeId: document.getElementById("componentMode").value,
                        title: document.querySelector('input[name="visibleDescription"]').value,
                        data: this.getNewSettings()
                    })
                });
                
                window.popupNotification.show(`Dynamic content '${document.querySelector('input[name="visibleDescription"]').value}' is succesvol opgeslagen.`, "info");
                this.loadComponentHistory();
            } catch (exception) {
                console.error(exception);
                kendo.alert("Er is iets fout gegaan met opslaan. Probeer het a.u.b. opnieuw");
            }

            window.processing.removeProcess(process);
        }

        /**
         * Retrieve the new values entered by the user and their properties.
         * */
        getNewSettings() {
            var settingsList = {};

            $("[data-property]").each(function (i, el) {
                var val;
                if (el.type === "checkbox") {
                    val = el.checked;
                } else if (el.title === "numeric") {
                    val = parseFloat(el.value)
                    if (!val) {
                        val = null;
                    }
                } else {
                    val = el.value;
                }

                settingsList[el.dataset.property] = val;
            });

            return settingsList;
        }

        /**
         * Loads the History HTML and updates the right panel.
         * */
        async loadComponentHistory() {
            const history = await Wiser2.api({
                url: `${this.settings.wiserApiRoot}dynamic-content/${this.settings.selectedId}/history`,
                dataType: "json",
                method: "GET"
            });

            const historyHtml = await Wiser2.api({
                url: `/Modules/DynamicContent/History`,
                method: "POST",
                contentType: "application/json",
                data: JSON.stringify(history)
            });

            document.getElementsByClassName("historyContainer")[0].innerHTML = historyHtml; 
            this.bindHistoryButtons();
        }

        async transformCodeMirrorViews() {
            await Misc.ensureCodeMirror();
            $("textarea[data-fieldtype][data-property]").each(function (i, el) {
                var cmObject = CodeMirror.fromTextArea(el, {
                    lineNumbers: true,
                    styleActiveLine: true,
                    matchBrackets: true,
                    mode: el.dataset.fieldtype
                });

                cmObject.on("change", function () {
                    cmObject.getTextArea().value = cmObject.getValue();
                });
            });
        }

        /**
         * Bind the buttons in the generated history html.
         * */
        bindHistoryButtons() {
            $("#revertChanges").hide();
            // Select history changes and change revert button visibility
            $(".col-6>.item").on("click", function (el) {
                var currentProperty = $(el.currentTarget).find("[data-historyproperty]").data("historyproperty");
                $(el.currentTarget.closest(".historyLine")).find(".col-6>.item").has("[data-historyproperty='" + currentProperty + "']").toggleClass("selected");

                if (document.querySelectorAll(".col-6>.item.selected").length) {
                    $("#revertChanges").show();
                    document.getElementsByClassName("btn-primary")[0].disabled = true;
                } else {
                    $("#revertChanges").hide();
                    document.getElementsByClassName("btn-primary")[0].disabled = false;
                }
            });

            // Clicking the revert button.
            $(".historyTagline button").on("click", async () => {
                const process = `revertChanges_${Date.now()}`;
                window.processing.addProcess(process);

                try {
                    const changeList = [];
                    $("[data-historyversion]:has(.selected)").each((i, versionElement) => {
                        const reverted = [];
                        $(versionElement).find(".selected [data-historyproperty]").each((ii, propertyElement) => {
                            if (!reverted.includes(propertyElement.dataset.historyproperty)) {
                                reverted.push(propertyElement.dataset.historyproperty);
                            }
                        });

                        changeList.push({
                            version: parseInt(versionElement.dataset.historyversion),
                            revertedProperties: reverted
                        });
                    });

                    await Wiser2.api({
                        url: `${this.settings.wiserApiRoot}dynamic-content/${this.settings.selectedId}/undo-changes`,
                        dataType: "json",
                        method: "POST",
                        contentType: "application/json",
                        data: JSON.stringify(changeList)
                    });
                
                    window.popupNotification.show(`Dynamic content(${this.settings.selectedId}) wijzigingen zijn succesvol teruggezet`, "info");
                    await this.loadComponentHistory();
                    await this.initCurrentComponentData();
                } catch (exception) {
                    console.error(exception);
                    kendo.alert("Er is iets fout gegaan met ongedaan maken van deze wijzigingen. Probeer het a.u.b. opnieuw");
                }

                window.processing.removeProcess(process);
            });
        }
    }

    // Initialize the DynamicItems class and make one instance of it globally available.
    window.DynamicContent = new DynamicContent(settings);
})(moduleSettings);