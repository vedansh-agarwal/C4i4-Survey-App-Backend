DROP DATABASE IF EXISTS `survey_app`;
CREATE DATABASE `survey_app`;
USE `survey_app`;

CREATE TABLE `survey_app`.`users` (
  `username` VARCHAR(20) NOT NULL,
  `name` VARCHAR(100) NOT NULL DEFAULT '',
  `country_prefix` VARCHAR(5) NULL,
  `mob_no` VARCHAR(15) NULL UNIQUE,
  `email` VARCHAR(200) NOT NULL UNIQUE,
  `password` VARCHAR(200) NOT NULL,
  `company_name` VARCHAR(100) NOT NULL DEFAULT '',
  `company_domain` VARCHAR(50) NOT NULL,
  `refresh_token` TEXT NULL,
  `admin_token` TEXT NULL,
  `created_on` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(),
  `updated_on` DATETIME NULL,
  `active_flag` INT NOT NULL DEFAULT 0,
  PRIMARY KEY (`username`));
  
CREATE TABLE `survey_app`.`questions` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `section_name` VARCHAR(100) NOT NULL,
  `subsection_name` VARCHAR(100) NULL,
  `question_number` INT NOT NULL,
  `question_description` VARCHAR(200) NOT NULL,
  `choice_details` TEXT NOT NULL,
  `batch_id` INT NOT NULL,
  `created_on` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(),
  `created_by` VARCHAR(20) NOT NULL DEFAULT 'admin',
  `updated_on` DATETIME NULL,
  `updated_by` VARCHAR(20) NULL,
  `question_help` TEXT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ques_no` (`section_name`, `question_number`, `batch_id`));

CREATE TABLE `survey_app`.`current_questions` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `section_name` VARCHAR(100) NOT NULL,
  `subsection_name` VARCHAR(100) NULL,
  `question_number` INT NOT NULL,
  `question_description` VARCHAR(200) NOT NULL,
  `choice_details` TEXT NOT NULL,
  `batch_id` INT NOT NULL,
  `created_on` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(),
  `created_by` VARCHAR(20) NOT NULL DEFAULT 'admin',
  `updated_on` DATETIME NULL,
  `updated_by` VARCHAR(20) NULL,
  `question_help` TEXT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ques_no` (`section_name`, `question_number`));
  
CREATE TABLE `survey_app`.`customers` (
  `customer_id` VARCHAR(40) NOT NULL,
  `customer_name` VARCHAR(100) NOT NULL DEFAULT "",
  `mobile_no` VARCHAR(15) NULL UNIQUE,
  `company_name` VARCHAR(100) NOT NULL DEFAULT "",
  `designation` VARCHAR(100) NULL,
  `company_email_id` VARCHAR(100) NOT NULL UNIQUE,
  `country` VARCHAR(100) NULL,
  `batch_id` INT NOT NULL,
  `created_on` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(),
  `updated_on` DATETIME NULL,
  `survey_report_url` VARCHAR(200) NULL,
  `survey_status` VARCHAR(100) NOT NULL DEFAULT 'Not Started',
  `registration_status` INT NOT NULL DEFAULT 0,
  `company_url` VARCHAR(200) DEFAULT NULL,
  `refresh_token` VARCHAR(300) DEFAULT NULL,
  PRIMARY KEY (`customer_id`));

CREATE TABLE `survey_app`.`customer_otp` (
  `created_on` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(),
  `email` VARCHAR(100) NOT NULL,
  `otp` VARCHAR(100) NOT NULL);

CREATE TABLE `survey_app`.`survey_answers` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `customer_id` VARCHAR(100) NOT NULL UNIQUE,
  `survey_answers` TEXT NOT NULL,
  `current_question` INT NOT NULL,
  `max_progress` INT NOT NULL DEFAULT 0,
  `current_section` VARCHAR (200) NOT NULL, 
  `survey_start_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(),
  `latest_update_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(),
  `survey_end_date` DATETIME NULL,
  `survey_complete_flag` INT NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`));
  
DELIMITER $$
CREATE TRIGGER `survey_app`.`insert_updated_questions` BEFORE UPDATE ON `current_questions` FOR EACH ROW
BEGIN
	INSERT INTO `questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`, `created_on`, `created_by`, `updated_on`, `updated_by`, `question_help`) 
	VALUE (NEW.`section_name`, NEW.`subsection_name`, NEW.`question_number`, NEW.`question_description`, NEW.`choice_details`, NEW.`batch_id`, NEW.`created_on`, NEW.`created_by`, NEW.`updated_on`, NEW.`updated_by`, NEW.`question_help`);
END$$
DELIMITER ;

DELIMITER $$
CREATE TRIGGER `survey_app`.`insert_new_questions` BEFORE INSERT ON `current_questions` FOR EACH ROW
BEGIN
	INSERT INTO `questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`, `created_on`, `created_by`, `updated_on`, `updated_by`, `question_help`) 
	VALUE (NEW.`section_name`, NEW.`subsection_name`, NEW.`question_number`, NEW.`question_description`, NEW.`choice_details`, NEW.`batch_id`, NEW.`created_on`, NEW.`created_by`, NEW.`updated_on`, NEW.`updated_by`, NEW.`question_help`);
END$$
DELIMITER ;

DELIMITER $$
CREATE TRIGGER `survey_app`.`insert_max_progress` BEFORE INSERT ON `survey_answers` FOR EACH ROW
BEGIN
	SET NEW.`max_progress` = NEW.`current_question`;
END$$
DELIMITER ;

DELIMITER $$
CREATE TRIGGER `survey_app`.`update_max_progress` BEFORE UPDATE ON `survey_answers` FOR EACH ROW
BEGIN
	SET NEW.`max_progress` = GREATEST(OLD.`max_progress`, NEW.`current_question`);
END$$
DELIMITER ;

INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE ('Section 2 - Company Profile', '', 1, 'Your Primary Industry', '[{"key":"a", "value":"Electronic Components", "rank":1}, {"key":"b", "value":"Telecommunications Equipment", "rank":1}, {"key":"c", "value":"Medical Equipment", "rank":1}, {"key":"d", "value":"Pharmaceuticals", "rank":1}, {"key":"e", "value":"Tires", "rank":1}, {"key":"f", "value":"Automobiles", "rank":1}, {"key":"g", "value":"Auto Parts", "rank":1}, {"key":"h", "value":"Household Appliance", "rank":1}, {"key":"i", "value":"Textile", "rank":1}, {"key":"j", "value":"Food Products", "rank":1}, {"key":"k", "value":"Tobacco", "rank":1}, {"key":"l", "value":"Construction", "rank":1}, {"key":"m", "value":"Cement", "rank":1}, {"key":"n", "value":"Aerospace", "rank":1}, {"key":"o", "value":"Defense", "rank":1}, {"key":"p", "value":"Electrical Components", "rank":1}, {"key":"q", "value":"Industrial Machinery", "rank":1}, {"key":"r", "value":"Metal Fabricating", "rank":1}, {"key":"s", "value":"Mining", "rank":1}, {"key":"t", "value":"Chemicals & Fertilizers", "rank":1}, {"key":"u", "value":"Oil & Gas", "rank":1}, {"key":"v", "value":"Energy", "rank":1}, {"key":"w", "value":"Diversified Congloremate", "rank":1}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE ('Section 2 - Company Profile', '', 2, 'Company Turnover (INR)', '[{"key":"a", "value":"< 100 Cr", "rank":1}, {"key":"b", "value":"< 500 Cr", "rank":0}, {"key":"c", "value":"< 1000 Cr", "rank":0}, {"key":"d", "value":"< 5000 Cr", "rank":0}, {"key":"e", "value":"> 5000 Cr", "rank":0}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE ('Section 2 - Company Profile', '', 3, 'Number of Employees', '[{"key":"a", "value":"<50", "rank":1}, {"key":"b", "value":"<100", "rank":1}, {"key":"c", "value":"<500", "rank":1}, {"key":"d", "value":"<1000", "rank":1}, {"key":"e", "value":">1000", "rank":1}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE ('Section 2 - Company Profile', '', 4, 'What is your primary business objective in next 2-3 years?', '[{"key":"a", "value":"Reduce Cost of Poor Quality", "rank":1}, {"key":"b", "value":"Reduce Inventory Levels", "rank":1}, {"key":"c", "value":"Reduce Product Time-to-Market", "rank":1}, {"key":"d", "value":"Improve Market Share/Revenue", "rank":1}, {"key":"e", "value":"Improve Customer Satisfaction", "rank":1}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE ('Section 2 - Company Profile', '', 5, 'Number of Factory locations', '[]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE ('Section 2 - Company Profile', '', 6, 'What are your customer channels', '[{"key":"a", "value":"B2B", "rank":1}, {"key":"b", "value":"B2B & B2C", "rank":1}, {"key":"c", "value":"B2C", "rank":1}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE ('Section 2 - Company Profile', '', 7, 'Which Markets do you operate in currently?', '[{"key":"a", "value":"India", "rank":1}, {"key":"b", "value":"India & Export", "rank":1}, {"key":"c", "value":"Export", "rank":1}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Digital Strategy  & Vision', 1, 'What best describes your organization strategy to digital transformation?', '[{ "key":"a", "value":"No articulated digital strategy in the organization", "rank":1},{ "key":"b", "value":"Digital Strategy articulated but is not used by the business operations", "rank":2},{ "key":"c", "value":"Digital Strategy articulated and is relevant and used  by the business operations", "rank":3},{ "key":"d", "value":"Digital Strategy is a dynamic and is buiness led and driven ", "rank":4},{ "key":"e", "value":"Digital Strategy is transformative and central to the future success of the organization", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Digital Strategy  & Vision', 2, 'What best describes your approach to developing new digital product and services?', '[{ "key":"a", "value":"We dont have any product or offerings leveraging digital technologies. We dont feel it is relevant for us", "rank":1},{ "key":"b", "value":"Our digital initiatives focus is to make small improvements on our product and offerings", "rank":2},{ "key":"c", "value":"Our digital initiatives are focused on building new offerings to our existing customers and markets", "rank":3},{ "key":"d", "value":"We continuously explore opportunities in adjacent markets and leverage digital to build products and services for new customer segments", "rank":4},{ "key":"e", "value":"We want to establish technology leadership in the markets we operate in and are building disruptive products and services leveraging digital ", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Data & Analytics', 3, 'What best describes the data maturity in your organization?', '[{ "key":"a", "value":"Data is kept mostly in employee systems in spreadsheets and logs", "rank":1},{ "key":"b", "value":"Transaction data from a siloed systems is in use in the organization", "rank":2},{ "key":"c", "value":"Structured data from multiple internal systems are integrated and used within organization", "rank":3},{ "key":"d", "value":"Real-time data sources like web data and IoT data is augmented to the existing data sources", "rank":4},{ "key":"e", "value":"Organization procures trusted external data to augment and enrich its own datasets ", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Data & Analytics', 4, 'What best describes the culture for data-driven decision making within your organization?', '[{ "key":"a", "value":"Decision makers rely on perceptions, historical decisions and non-validated beliefs.", "rank":1},{ "key":"b", "value":"Decision makers recognize benefits of data analytics to support decision making but don�t leverage analytics consistently.", "rank":2},{ "key":"c", "value":"Decision makers adopt data analytics for all decisions, including key investments and resource allocation.", "rank":3},{ "key":"d", "value":"Decision makers leverage analytics across the organization to support business decisions.", "rank":4},{ "key":"e", "value":"Decision makers search for new ways to use advanced analytics to support business decisions.", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Organization & Skills', 5, 'Who drives digital transformation agenda in the organization?', '[{ "key":"a", "value":"There is no single ownership for digital transformation within organization. It is ad-hoc", "rank":1},{ "key":"b", "value":"IT team drives the digital transformation agenda", "rank":2},{ "key":"c", "value":"Digital Transformation is owned and driven by respective departments", "rank":3},{ "key":"d", "value":"CEO has an additional responsibility of driving the digital transformation in the organization", "rank":4},{ "key":"e", "value":"CDO, with dedicated P/L,reporting to the board, drives the digital transformation agenda", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Organization & Skills', 6, 'How best describes your approach to creating the digital talent pool within the organization?', '[{ "key":"a", "value":"We dont have a strategy in place to build new talent pool in the organization. Few skills attached to the functions", "rank":1},{ "key":"b", "value":"Pockets of skills with organization. Not connected and no skill management", "rank":2},{ "key":"c", "value":"Digital skills recognized as a key business differentitor and some hiring and training programs launched", "rank":3},{ "key":"d", "value":"Company-wide initiative to train and upskill existing resources and deploy them on new projects", "rank":4},{ "key":"e", "value":"Future business strategy is build around digital capabilities. Specific role based training and upskilling program in place across all layers and functions of the company", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Process & Technology', 7, 'How are processes defined within the organization?', '[{ "key":"a", "value":"Processes are manual and ad-hoc. There is little or no process documentation or control", "rank":1},{ "key":"b", "value":"Processes are partly digitized but there is lack of control and adoption resulting in high process variations", "rank":2},{ "key":"c", "value":"Processes are standardized across business units and there are controls to ensure high adoption and low process variations", "rank":3},{ "key":"d", "value":"E2E processes are digitized and standardized with clear process ownership and metrics defined", "rank":4},{ "key":"e", "value":"Organization is continuously looking for ways to improve business processes with a clear focus on evolving customer needs", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 3 - Organization Digital Maturity', 'Process & Technology', 8, 'What is the organization approach to digital technology acquisition?', '[{ "key":"a", "value":"Organization does not believe digital technology is a business differentiator and does not make investments beyond basic spreadsheets", "rank":1},{ "key":"b", "value":"Organization considers technology as a cost function and makes investment based on core -  financial, regulatory or specific customer requirements", "rank":2},{ "key":"c", "value":"Organization makes some technology investments outside of core requirements but those are internally focused and made for improving process efficiencies", "rank":3},{ "key":"d", "value":"There is an understanding that technology is a key business enabler and decisions on technology is both external and internal facing. A customer metric based business case is required for investment decision", "rank":4},{ "key":"e", "value":"Company has adopted a forward looking platform approach to technology. The technology backbone supports rapid development and deployment of products and services", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Order Management', 1, 'What channels do the customer usually use to share order information like contracts, POs, drawings etc. with you?', '[{ "key":"a", "value":"We collect customer requirements either over phone or via a face-to-face meeting", "rank":1},{ "key":"b", "value":"Details are shared via e-mail to the sales team", "rank":2},{ "key":"c", "value":"Our teams can download the required documents from a vendor portal owned by customer", "rank":3},{ "key":"d", "value":"We use technologies like EDI to share and receive information from our customers", "rank":4}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Order Management', 2, 'How does the customer find out the status of his order with us?', '[{ "key":"a", "value":"Customer needs to have multiple calls /meetings with us to know about the order status", "rank":1},{ "key":"b", "value":"Customer is able to track the status of his order by logging into an online order tracking tool provided by us", "rank":2},{ "key":"c", "value":"We sent automated alerts to the customer via SMS/e-mail on the order status on a periodic basis", "rank":3},{ "key":"d", "value":"We use advanced analytical tools to predict potential issues about an order and provide alerts to the customer in real-time", "rank":4}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Supplier Performance', 3, 'What channels do you usually use to share order information like contracts, POs, drawings etc. with suppliers?', '[{ "key":"a", "value":"We provide our requirements either over phone or via a face-to-face meeting", "rank":1},{ "key":"b", "value":"Details are shared via e-mail to the supplier team", "rank":2},{ "key":"c", "value":"Our suppliers can download the required documents from a vendor portal owned by us", "rank":3},{ "key":"d", "value":"We use technologies like EDI to share and receive information from our suppliers", "rank":4}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Supplier Performance', 4, 'How do you measure supplier perfomance?', '[{ "key":"a", "value":"Reactive, only when there is an issue related to an order", "rank":1},{ "key":"b", "value":"All supplier order data is manually monitored and reported for control purposes", "rank":2},{ "key":"c", "value":"We have developed system based dashboards to monitor supplier overall performance ", "rank":3},{ "key":"d", "value":"We leverage advanced analytics solutions to monitor and evaluate supplier performance", "rank":4}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Production Planning and Control', 5, 'How is the product planning done in the organization today?', '[{ "key":"a", "value":"Planning process is manual and based on usage of paper based planning boards", "rank":1},{ "key":"b", "value":"We use excel worksheets to do the planning with manual controls with the planner", "rank":2},{ "key":"c", "value":"We use demand forecasting tools and system based material planning in the organization", "rank":3},{ "key":"d", "value":"We have a robust S&OP process supported by advanced analytics and collaborative tools for planning", "rank":4}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Production Planning and Control', 6, 'How are the inventory stock levels for raw, WIP and finished products monitored?', '[{ "key":"a", "value":"No systematic monitoring or control", "rank":1},{ "key":"b", "value":"Manual in analogous form, paper- based / use of planning boards", "rank":2},{ "key":"c", "value":"Based on spreadsheets, including forecasts of some weeks", "rank":3},{ "key":"d", "value":"Through IT system with real-time information (ERP / MES / advanced planning system)", "rank":4},{ "key":"e", "value":"Sensor or tracking technologies are used for automatic monitoring of inventory", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Production', 7, 'How is production data generated and captured in the organization today?', '[{ "key":"a", "value":"Currently we use manual log-book entry to capture and update production data which is used for doing end-of-shift reporting", "rank":1},{ "key":"b", "value":"We use digital tabs which operators can use to directly enter production data which is updated in the reporting system ", "rank":2},{ "key":"c", "value":"Wherever possible we extract the real-time equipment,operator and material consumption data and use it for basic reporting", "rank":3},{ "key":"d", "value":"We extract granual equipment, operator and material consulption data and apply advanced analytics to identify gaps and continuously improve", "rank":4}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Quality', 8, 'What best describes your approach to quality?', '[{ "key":"a", "value":"Quality processes are manual and reactive with little control. Quality is seen as responsibility of the quality department", "rank":1},{ "key":"b", "value":"Quality processes are system driven with control mechanisms in place. Quality is recognized as an organizational initiative", "rank":2},{ "key":"c", "value":"Organization leverages automation and poka-yoke tools to reduce human error and improve quality", "rank":3},{ "key":"d", "value":"Organization collects and analyzes granual operational data to identify root-causes of poor quality and initiatives changes to improve quality continuously", "rank":4}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Maintenance', 9, 'Which maintenance approach best describes the way maintenance is done currently?', '[{ "key":"a", "value":"We conduct only breakdown maintenance in our plants", "rank":1},{ "key":"b", "value":"We conduct periodic, time based maintenance in our plants", "rank":2},{ "key":"c", "value":"Measure and fix: Using sensor-based condition monitoring for planning maintenance", "rank":3},{ "key":"d", "value":"Preventive: Using condition monitoring and historical data to improve maintenance planning", "rank":4},{ "key":"e", "value":"Predictive: Predict machine reliability by using sensing data and analytics", "rank":5}]', 1);
INSERT INTO `current_questions` (`section_name`, `subsection_name`, `question_number`, `question_description`, `choice_details`, `batch_id`) VALUE('Section 4 - Functional Maturity', 'Energy and Sustainability', 10, 'What is the organization approach to for sustainability and energy reduction?', '[{ "key":"a", "value":"Organization has no strategy or plans in place for energy and sustainability", "rank":1},{ "key":"b", "value":"Organization has undertaken initiatives like placing smart meters to monitor real-time energy consumption", "rank":2},{ "key":"c", "value":"Organization does an annual reporting of its internal carbon footprint (scope 1) and has in place a sustainability target and roadmap", "rank":3},{ "key":"d", "value":"Organization has systems in place for monitoring and improving scope 2 and scope 3 carbon footprint", "rank":4}]', 1);